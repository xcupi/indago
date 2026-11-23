package llm

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Windows file locks require a file handle rather than a directory handle.
func lockStore(path string) (func(), error) {
	lock, err := os.OpenFile(filepath.Join(path, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var overlap windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(lock.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlap); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("llm: lock configuration store: %w", err)
	}
	return func() { _ = lock.Close() }, nil
}

// Windows does not support syncing directories through a regular file handle.
func syncStoreDir(string) error { return nil }
