package fsys

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
)

// Mem is an in-memory file system that models durability: file contents
// survive a crash only up to the last Sync of the file, and creations,
// renames and removals only after a SyncDir of their directory. Directories
// created with MkdirAll are durable at once. Mem is safe for concurrent use.
type Mem struct {
	mu      sync.Mutex
	live    map[string]*inode
	durable map[string]*inode
	dirs    map[string]bool

	// LieSync makes File.Sync report success without making the content
	// durable (a disk that loses acknowledged writes).
	LieSync bool
}

// inode is a file: its content and what of it is durable. While the file
// is only appended to, the durable content is the prefix data[:synced];
// a write into that prefix first copies it to kept.
type inode struct {
	data   []byte
	synced int
	kept   []byte // durable content when the prefix was overwritten, else nil
}

func (ino *inode) durable() []byte {
	if ino.kept != nil {
		return ino.kept
	}
	return ino.data[:ino.synced]
}

// touch prepares a change of data at offsets >= off.
func (ino *inode) touch(off int) {
	if ino.kept == nil && off < ino.synced {
		ino.kept = bytes.Clone(ino.data[:ino.synced])
	}
}

// NewMem returns an empty file system with the root directory.
func NewMem() *Mem {
	return &Mem{live: map[string]*inode{}, durable: map[string]*inode{}, dirs: map[string]bool{"/": true, ".": true}}
}

func clean(name string) string { return path.Clean(name) }

func notExist(op, name string) error {
	return &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
}

// OpenFile implements FS.
func (m *Mem) OpenFile(name string, flag int, _ fs.FileMode) (File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name = clean(name)
	if !m.dirs[path.Dir(name)] {
		return nil, notExist("open", name)
	}
	ino, ok := m.live[name]
	switch {
	case !ok && flag&os.O_CREATE == 0:
		return nil, notExist("open", name)
	case ok && flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0:
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrExist}
	case !ok:
		ino = &inode{}
		m.live[name] = ino
	}
	if flag&os.O_TRUNC != 0 {
		ino.touch(0)
		ino.data = nil
	}
	acc := flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)
	return &memFile{m: m, ino: ino, name: name, appendMode: flag&os.O_APPEND != 0,
		read: acc == os.O_RDONLY || acc == os.O_RDWR, write: acc == os.O_WRONLY || acc == os.O_RDWR}, nil
}

// ReadFile implements FS.
func (m *Mem) ReadFile(name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ino, ok := m.live[clean(name)]
	if !ok {
		return nil, notExist("read", name)
	}
	return bytes.Clone(ino.data), nil
}

// Size implements FS.
func (m *Mem) Size(name string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ino, ok := m.live[clean(name)]
	if !ok {
		return 0, notExist("stat", name)
	}
	return int64(len(ino.data)), nil
}

// Rename implements FS.
func (m *Mem) Rename(oldName, newName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	oldName, newName = clean(oldName), clean(newName)
	ino, ok := m.live[oldName]
	if !ok {
		return notExist("rename", oldName)
	}
	if !m.dirs[path.Dir(newName)] {
		return notExist("rename", newName)
	}
	delete(m.live, oldName)
	m.live[newName] = ino
	return nil
}

// Remove implements FS.
func (m *Mem) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	name = clean(name)
	if _, ok := m.live[name]; !ok {
		return notExist("remove", name)
	}
	delete(m.live, name)
	return nil
}

// MkdirAll implements FS.
func (m *Mem) MkdirAll(dir string, _ fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for d := clean(dir); !m.dirs[d]; d = path.Dir(d) {
		m.dirs[d] = true
	}
	return nil
}

// ReadDir implements FS.
func (m *Mem) ReadDir(dir string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	dir = clean(dir)
	if !m.dirs[dir] {
		return nil, notExist("readdir", dir)
	}
	seen := map[string]bool{}
	for name := range m.live { //wbft:unordered the names are sorted below
		if path.Dir(name) == dir {
			seen[path.Base(name)] = true
		}
	}
	for d := range m.dirs { //wbft:unordered the names are sorted below
		if d != dir && path.Dir(d) == dir {
			seen[path.Base(d)] = true
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen { //wbft:unordered the names are sorted below
		names = append(names, n)
	}
	slices.Sort(names)
	return names, nil
}

// SyncDir implements FS.
func (m *Mem) SyncDir(dir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	dir = clean(dir)
	if !m.dirs[dir] {
		return notExist("syncdir", dir)
	}
	for name := range m.durable { //wbft:unordered every entry of dir is updated
		if path.Dir(name) == dir {
			if _, ok := m.live[name]; !ok {
				delete(m.durable, name)
			}
		}
	}
	for name, ino := range m.live { //wbft:unordered every entry of dir is updated
		if path.Dir(name) == dir {
			m.durable[name] = ino
		}
	}
	return nil
}

// Crash drops what a crash would lose: every name not made durable by
// SyncDir disappears, and every file keeps the content of its last Sync. When
// r is not nil, a file that was only appended to since its last Sync keeps a
// random prefix of the unsynced bytes as well (a torn write).
func (m *Mem) Crash(r *rand.Rand) {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.durable))
	for name := range m.durable { //wbft:unordered the names are sorted below
		names = append(names, name)
	}
	slices.Sort(names)
	fresh := map[*inode]*inode{}
	live := map[string]*inode{}
	durable := map[string]*inode{}
	for _, name := range names {
		old := m.durable[name]
		n, ok := fresh[old]
		if !ok {
			data := bytes.Clone(old.durable())
			if r != nil && old.kept == nil && len(old.data) > old.synced {
				k := r.IntN(len(old.data) - old.synced + 1)
				data = append(data, old.data[old.synced:old.synced+k]...)
			}
			n = &inode{data: data}
			n.synced = len(n.data)
			if r != nil && old.kept == nil && len(old.data) > old.synced {
				// The torn bytes were not synced.
				n.synced = len(old.durable())
			}
			fresh[old] = n
		}
		live[name] = n
		durable[name] = n
	}
	m.live, m.durable = live, durable
}

// Corrupt applies f to the content of a file as a disk fault would: the
// change is durable.
func (m *Mem) Corrupt(name string, f func([]byte) []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ino, ok := m.live[clean(name)]
	if !ok {
		return notExist("corrupt", name)
	}
	ino.data = f(bytes.Clone(ino.data))
	ino.synced, ino.kept = len(ino.data), nil
	return nil
}

// Dump returns the names and contents of all files under dir, for copying
// simulation outputs out of the file system.
func (m *Mem) Dump(dir string) map[string][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	dir = clean(dir)
	out := map[string][]byte{}
	for name, ino := range m.live { //wbft:unordered the result is a map
		if strings.HasPrefix(name, dir+"/") {
			out[name] = bytes.Clone(ino.data)
		}
	}
	return out
}

type memFile struct {
	m          *Mem
	ino        *inode
	name       string
	off        int64
	appendMode bool
	read       bool
	write      bool
	closed     bool
}

func (f *memFile) Read(p []byte) (int, error) {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if f.closed || !f.read {
		return 0, fmt.Errorf("fsys: read %s: bad file", f.name)
	}
	if f.off >= int64(len(f.ino.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.ino.data[f.off:])
	f.off += int64(n)
	return n, nil
}

func (f *memFile) Write(p []byte) (int, error) {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if f.closed || !f.write {
		return 0, fmt.Errorf("fsys: write %s: bad file", f.name)
	}
	if f.appendMode {
		f.off = int64(len(f.ino.data))
	}
	f.ino.touch(int(f.off))
	end := f.off + int64(len(p))
	if end > int64(len(f.ino.data)) {
		f.ino.data = append(f.ino.data, make([]byte, end-int64(len(f.ino.data)))...)
	}
	copy(f.ino.data[f.off:], p)
	f.off = end
	return len(p), nil
}

func (f *memFile) Close() error {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	f.closed = true
	return nil
}

func (f *memFile) Sync() error {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if f.closed {
		return fmt.Errorf("fsys: sync %s: file closed", f.name)
	}
	if !f.m.LieSync {
		f.ino.synced, f.ino.kept = len(f.ino.data), nil
	}
	return nil
}

func (f *memFile) Truncate(size int64) error {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	f.ino.touch(int(size))
	if size < int64(len(f.ino.data)) {
		f.ino.data = f.ino.data[:size]
	} else {
		f.ino.data = append(f.ino.data, make([]byte, size-int64(len(f.ino.data)))...)
	}
	return nil
}

func (f *memFile) Size() (int64, error) {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	return int64(len(f.ino.data)), nil
}
