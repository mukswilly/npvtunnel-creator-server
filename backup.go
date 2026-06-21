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

// runBackupSubcommand handles `creator-server backup ...`. Bundles the
// state directory (creator key, audit salt, configs.json,
// redemption-tokens.json) into one gzipped tar so an operator can copy it
// off the box in a single step. The creator key is the irreplaceable part
// — losing it breaks every recipient — so this exists to make "back it up"
// one command instead of a manual file hunt.
//
// The ACME certificate cache (<state-dir>/acme) is skipped: those certs are
// freely re-obtainable from Let's Encrypt and don't need backing up.
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
	info, err := os.Stat(*stateDir)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "backup: -state-dir %q is not a directory\n", *stateDir)
		return 1
	}

	f, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "backup: create output:", err)
		return 1
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	// Never archive our own output file — if -out lives inside the state
	// dir, including it would grow while being copied ("write too long").
	outAbs, _ := filepath.Abs(*out)

	var count int
	var total int64
	walkErr := filepath.WalkDir(*stateDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip the ACME cert cache — renewable, not worth bundling.
			if d.Name() == "acme" && path != *stateDir {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip transient write-then-rename temp files.
		if strings.HasSuffix(d.Name(), ".tmp") {
			return nil
		}
		// Skip the archive we're currently writing.
		if pathAbs, aerr := filepath.Abs(path); aerr == nil && pathAbs == outAbs {
			return nil
		}
		rel, err := filepath.Rel(*stateDir, path)
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(tw, src)
		src.Close()
		if copyErr != nil {
			return copyErr
		}
		count++
		total += n
		return nil
	})
	if walkErr != nil {
		fmt.Fprintln(os.Stderr, "backup: archive:", walkErr)
		return 1
	}
	if err := tw.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "backup: finalize tar:", err)
		return 1
	}
	if err := gz.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "backup: finalize gzip:", err)
		return 1
	}

	fmt.Fprintf(os.Stderr,
		"backup: wrote %d files (%d bytes) to %s\n"+
			"        Store this OFF the server — it contains creator-key.pem,\n"+
			"        your signing identity. Anyone who has it can issue as you.\n",
		count, total, *out)
	return 0
}
