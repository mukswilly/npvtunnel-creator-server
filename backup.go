package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// writeStateBackup bundles the state directory (creator key, audit salt,
// configs.json, redemption-tokens.json) into one gzipped tar at out, and
// returns how many files and bytes it archived. The ACME certificate cache
// (<state-dir>/acme) and transient *.tmp files are skipped — those are
// renewable / disposable. The output file is never archived into itself.
//
// Shared by `creator-server backup` and the management console's backup
// action so both produce the same artifact.
func writeStateBackup(stateDir, out string) (files int, bytes int64, err error) {
	info, serr := os.Stat(stateDir)
	if serr != nil || !info.IsDir() {
		return 0, 0, fmt.Errorf("state dir %q is not a directory", stateDir)
	}

	f, ferr := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if ferr != nil {
		return 0, 0, fmt.Errorf("create output: %w", ferr)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	outAbs, _ := filepath.Abs(out)

	walkErr := filepath.WalkDir(stateDir, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			if d.Name() == "acme" && path != stateDir {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".tmp") {
			return nil
		}
		if pathAbs, aerr := filepath.Abs(path); aerr == nil && pathAbs == outAbs {
			return nil
		}
		rel, rerr := filepath.Rel(stateDir, path)
		if rerr != nil {
			return rerr
		}
		fi, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		hdr, herr := tar.FileInfoHeader(fi, "")
		if herr != nil {
			return herr
		}
		hdr.Name = filepath.ToSlash(rel)
		if werr := tw.WriteHeader(hdr); werr != nil {
			return werr
		}
		src, oerr := os.Open(path)
		if oerr != nil {
			return oerr
		}
		n, cerr := io.Copy(tw, src)
		src.Close()
		if cerr != nil {
			return cerr
		}
		files++
		bytes += n
		return nil
	})
	if walkErr != nil {
		return files, bytes, walkErr
	}
	if cerr := tw.Close(); cerr != nil {
		return files, bytes, fmt.Errorf("finalize tar: %w", cerr)
	}
	if cerr := gz.Close(); cerr != nil {
		return files, bytes, fmt.Errorf("finalize gzip: %w", cerr)
	}
	return files, bytes, nil
}

// runBackupSubcommand handles `creator-server backup ...` — a thin CLI
// wrapper over writeStateBackup. The creator key is the irreplaceable part
// (losing it breaks every recipient), so this makes "back it up" one command.
func runBackupSubcommand(args []string) int {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stateDir := fs.String("state-dir", "", "state directory to back up (required)")
	out := fs.String("out", "creator-server-state-backup.tar.gz",
		"output archive path (gzipped tar, written 0600)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *stateDir == "" {
		fmt.Fprintln(os.Stderr, "backup: -state-dir is required")
		fs.Usage()
		return 2
	}

	n, total, err := writeStateBackup(*stateDir, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "backup:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr,
		"backup: wrote %d files (%d bytes) to %s\n"+
			"        Store this OFF the server — it contains creator-key.pem,\n"+
			"        your signing identity. Anyone who has it can issue as you.\n",
		n, total, *out)
	return 0
}
