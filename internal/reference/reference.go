// Package reference opens the local reference file read-only.
package reference

import (
	"fmt"
	"os"
	"time"
)

// File is a read-only handle on the reference. RangeProbe never writes to it.
type File struct {
	f       *os.File
	path    string
	size    int64
	modTime time.Time
}

// Open opens a regular file for reading.
func Open(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("reference %q is not a regular file", path)
	}
	return &File{f: f, path: path, size: st.Size(), modTime: st.ModTime()}, nil
}

// Path returns the path given to Open.
func (r *File) Path() string { return r.path }

// Size returns the length of the file when it was opened.
func (r *File) Size() int64 { return r.size }

// ReadAt implements io.ReaderAt.
func (r *File) ReadAt(p []byte, off int64) (int, error) { return r.f.ReadAt(p, off) }

// Changed reports whether the file's size or modification time differ from
// the values observed at Open.
func (r *File) Changed() bool {
	st, err := os.Stat(r.path)
	if err != nil {
		return true
	}
	return st.Size() != r.size || !st.ModTime().Equal(r.modTime)
}

// Close releases the handle.
func (r *File) Close() error { return r.f.Close() }
