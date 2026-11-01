// Package report renders a model.Report as text, JSON or standalone HTML
// and writes report files safely.
package report

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrExists is returned when the destination exists and overwriting was not
// requested.
var ErrExists = errors.New("file exists (use --force to overwrite)")

// WriteFile writes data to path atomically: the content goes to a temporary
// file in the same directory, is synced, and is then moved into place, so a
// reader never sees a partial report. Without force an existing path is never
// replaced, and the check-and-create step is a hard link, which fails if the
// name appeared concurrently. Symbolic links and directories are never
// replaced.
func WriteFile(path string, data []byte, force bool) (err error) {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	if st, lerr := os.Lstat(path); lerr == nil {
		if !force {
			return fmt.Errorf("%s: %w", path, ErrExists)
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("%s exists and is not a regular file; refusing to replace it", path)
		}
	} else if !errors.Is(lerr, fs.ErrNotExist) {
		return lerr
	}
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if force {
		return os.Rename(tmpName, path)
	}
	lerr := os.Link(tmpName, path)
	switch {
	case lerr == nil:
		return os.Remove(tmpName)
	case errors.Is(lerr, fs.ErrExist):
		return fmt.Errorf("%s: %w", path, ErrExists)
	}
	// Hard links unsupported on this filesystem: fall back to rename after a
	// last existence check (a narrow race remains and is documented).
	if _, serr := os.Lstat(path); serr == nil {
		return fmt.Errorf("%s: %w", path, ErrExists)
	}
	return os.Rename(tmpName, path)
}
