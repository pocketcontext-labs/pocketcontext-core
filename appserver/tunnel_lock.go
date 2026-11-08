package appserver

import (
	"errors"
	"os"
	"path/filepath"
)

// AcquireTunnelLock serializes serving and identity rotation on this machine.
// Closing the descriptor releases the OS lock even after a process crash.
func AcquireTunnelLock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "tunnel.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, errors.New("a tunnel for this knowledge base is already running; stop it before serving or rotating its address")
	}
	return func() { _ = f.Close() }, nil
}
