// Package atomicfile holds the crash- and sync-safe file primitives shared by
// the server, the profile registry and the tunnel. It has no dependencies.
package atomicfile

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// RandomHex returns n random bytes as hexadecimal.
func RandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// WriteAtomic replaces path through a temporary file in the same folder.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(temp, mode); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return RenameRetry(temp, path)
}

// RenameRetry replaces dst. Sync clients and virus scanners briefly hold files
// open on Windows, which makes an otherwise valid rename fail.
func RenameRetry(src, dst string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if err = os.Rename(src, dst); err == nil {
			return nil
		}
		time.Sleep(time.Duration(50*(attempt+1)) * time.Millisecond)
	}
	return err
}

// CopyFile copies src to dst privately and syncs it.
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	return err
}

// FileSHA256 returns the lowercase hex digest of a file's bytes.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
