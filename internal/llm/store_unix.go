//go:build unix

package llm

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Lock the directory so independently opened stores, including the CLI and
// server, serialize their transactions without leaving a stale lock file.
func lockStore(path string) (func(), error) {
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	for {
		err = unix.Flock(int(dir.Fd()), unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("llm: lock configuration store: %w", err)
	}
	return func() { _ = dir.Close() }, nil
}

func syncStoreDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("llm: sync configuration directory: %w", err)
	}
	return nil
}
