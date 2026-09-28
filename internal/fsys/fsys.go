// Package fsys is the small file-system interface of the packages that keep
// durable state (wal, privval, observe/journal): open, write, sync, rename
// and directory sync. OS is the operating-system implementation; Mem is an
// in-memory implementation that models what survives a crash, for the
// deterministic simulator and the crash tests.
package fsys

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"slices"
)

// File is an open file.
type File interface {
	io.Reader
	io.Writer
	io.Closer
	// Sync commits the file's content to stable storage.
	Sync() error
	// Truncate changes the size of the file.
	Truncate(size int64) error
	// Size returns the current size of the file.
	Size() (int64, error)
}

// FS is a file system. Names use the separator of the host ("/" in Mem).
type FS interface {
	// OpenFile opens a file with the flags of os.OpenFile (O_RDONLY,
	// O_WRONLY, O_RDWR, O_CREATE, O_EXCL, O_TRUNC, O_APPEND).
	OpenFile(name string, flag int, perm fs.FileMode) (File, error)
	// ReadFile returns the whole content of a file.
	ReadFile(name string) ([]byte, error)
	// Size returns the size of a file.
	Size(name string) (int64, error)
	// Rename renames a file; the new name replaces an existing file.
	Rename(oldName, newName string) error
	// Remove removes a file.
	Remove(name string) error
	// MkdirAll creates a directory and its parents.
	MkdirAll(dir string, perm fs.FileMode) error
	// ReadDir returns the names of the entries of dir in ascending order.
	ReadDir(dir string) ([]string, error)
	// SyncDir commits the entries of dir (creations, renames, removals) to
	// stable storage.
	SyncDir(dir string) error
}

// ErrNotExist is returned for a missing file; errors.Is(err, fs.ErrNotExist)
// also holds.
var ErrNotExist = fs.ErrNotExist

// IsNotExist reports whether err says that a file does not exist.
func IsNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// OS is the file system of the operating system.
type OS struct{}

type osFile struct{ *os.File }

func (f osFile) Size() (int64, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// OpenFile implements FS.
func (OS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return osFile{f}, nil
}

// ReadFile implements FS.
func (OS) ReadFile(name string) ([]byte, error) { return os.ReadFile(name) }

// Size implements FS.
func (OS) Size(name string) (int64, error) {
	st, err := os.Stat(name)
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// Rename implements FS.
func (OS) Rename(oldName, newName string) error { return os.Rename(oldName, newName) }

// Remove implements FS.
func (OS) Remove(name string) error { return os.Remove(name) }

// MkdirAll implements FS.
func (OS) MkdirAll(dir string, perm fs.FileMode) error { return os.MkdirAll(dir, perm) }

// ReadDir implements FS.
func (OS) ReadDir(dir string) ([]string, error) {
	es, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(es))
	for _, e := range es {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names, nil
}

// SyncDir implements FS.
func (OS) SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// WriteFileAtomic replaces name with data so that after a crash the file
// holds either the old or the new content: it writes a temporary file,
// syncs it, renames it over name and syncs the directory.
func WriteFileAtomic(fsys FS, dir, name string, data []byte, perm fs.FileMode) error {
	tmp := name + ".tmp"
	f, err := fsys.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := fsys.Rename(tmp, name); err != nil {
		return err
	}
	return fsys.SyncDir(dir)
}
