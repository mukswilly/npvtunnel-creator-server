package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// atomicWriteFile replaces path without changing the ownership or mode of an
// existing state file. For a new file it inherits the state directory's owner
// and group and applies defaultMode. This keeps an administrative dashboard
// session from making state unreadable by the unprivileged API service.
func atomicWriteFile(path string, data []byte, defaultMode os.FileMode) error {
	dir := filepath.Dir(path)
	ownerInfo, err := os.Stat(path)
	mode := defaultMode
	if err == nil {
		mode = ownerInfo.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat target: %w", err)
	} else {
		ownerInfo, err = os.Stat(dir)
		if err != nil {
			return fmt.Errorf("stat state directory: %w", err)
		}
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary file mode: %w", err)
	}
	if uid, gid, ok := fileOwner(ownerInfo); ok {
		if current, statErr := tmp.Stat(); statErr != nil {
			return fmt.Errorf("stat temporary file: %w", statErr)
		} else if currentUID, currentGID, currentOK := fileOwner(current); currentOK &&
			(currentUID != uid || currentGID != gid) {
			if err := os.Chown(tmpPath, uid, gid); err != nil {
				return fmt.Errorf("preserve state ownership: %w", err)
			}
		}
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	closed = true
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}

	// Best-effort directory sync makes the rename durable on filesystems that
	// support it. The state replacement has already succeeded, so a platform
	// that rejects directory fsync must not turn a successful mutation into a
	// retryable application error.
	if directory, openErr := os.Open(dir); openErr == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func fileOwner(info os.FileInfo) (uid, gid int, ok bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(stat.Uid), int(stat.Gid), true
}
