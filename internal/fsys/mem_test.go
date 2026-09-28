package fsys

import (
	"bytes"
	"math/rand/v2"
	"os"
	"testing"
)

func write(t *testing.T, m *Mem, name string, data []byte, sync bool) {
	t.Helper()
	f, err := m.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	if sync {
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMemCrash(t *testing.T) {
	m := NewMem()
	if err := m.MkdirAll("/d", 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, m, "/d/a", []byte("synced"), true)
	write(t, m, "/d/b", []byte("never in dir"), true)
	if err := m.SyncDir("/d"); err != nil {
		t.Fatal(err)
	}
	write(t, m, "/d/a", []byte("-unsynced"), false)
	write(t, m, "/d/c", []byte("new"), true) // name not synced
	if err := m.Remove("/d/b"); err != nil {
		t.Fatal(err)
	}
	m.Crash(nil)
	if b, _ := m.ReadFile("/d/a"); !bytes.Equal(b, []byte("synced")) {
		t.Fatalf("a: %q", b)
	}
	if _, err := m.ReadFile("/d/b"); err != nil {
		t.Fatal("a removal without SyncDir must not survive")
	}
	if _, err := m.ReadFile("/d/c"); !IsNotExist(err) {
		t.Fatal("a creation without SyncDir must not survive")
	}
	// Torn writes keep a prefix of the unsynced tail.
	for seed := uint64(0); seed < 20; seed++ {
		m := NewMem()
		_ = m.MkdirAll("/d", 0o700)
		write(t, m, "/d/a", []byte("head"), true)
		_ = m.SyncDir("/d")
		write(t, m, "/d/a", []byte("tail-bytes"), false)
		m.Crash(rand.New(rand.NewPCG(seed, 0)))
		b, _ := m.ReadFile("/d/a")
		if !bytes.HasPrefix([]byte("headtail-bytes"), b) || len(b) < 4 {
			t.Fatalf("seed %d: %q", seed, b)
		}
	}
	// A lying disk loses synced data.
	m = NewMem()
	_ = m.MkdirAll("/d", 0o700)
	m.LieSync = true
	write(t, m, "/d/a", []byte("lost"), true)
	_ = m.SyncDir("/d")
	m.Crash(nil)
	if b, _ := m.ReadFile("/d/a"); len(b) != 0 {
		t.Fatalf("lying sync kept %q", b)
	}
}

func TestAtomicWrite(t *testing.T) {
	for _, fs := range []FS{NewMem(), OS{}} {
		dir := "/d"
		if _, ok := fs.(OS); ok {
			dir = t.TempDir()
		}
		_ = fs.MkdirAll(dir, 0o700)
		name := dir + "/f"
		for _, s := range []string{"one", "two"} {
			if err := WriteFileAtomic(fs, dir, name, []byte(s), 0o600); err != nil {
				t.Fatal(err)
			}
			if b, _ := fs.ReadFile(name); string(b) != s {
				t.Fatalf("%q", b)
			}
		}
		names, _ := fs.ReadDir(dir)
		if len(names) != 1 {
			t.Fatalf("entries: %v", names)
		}
	}
}
