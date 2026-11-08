package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteAtomicCopyAndHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := WriteAtomic(path, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(path, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "synthetic" {
		t.Fatalf("read back: %q %v", data, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("mode: %v %v", info.Mode(), err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary left behind: %v", entries)
	}
	copied := filepath.Join(dir, "copy.txt")
	if err := CopyFile(path, copied); err != nil {
		t.Fatal(err)
	}
	a, _ := FileSHA256(path)
	b, _ := FileSHA256(copied)
	if a == "" || a != b {
		t.Fatalf("hash mismatch %q %q", a, b)
	}
	if len(RandomHex(8)) != 16 {
		t.Fatal("hex length")
	}
}
