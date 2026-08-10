package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// writeStateBackup writes a gzipped tar of stateDir to out (mode 0600). It skips
// the acme cache subdirectory (re-fetchable), .tmp scratch files, and the output
// archive itself so a backup written inside the state dir doesn't capture itself.
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
