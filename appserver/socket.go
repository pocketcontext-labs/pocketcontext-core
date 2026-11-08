package appserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type socketContextKey struct{}

func socketRequest(r *http.Request) bool {
	v, _ := r.Context().Value(socketContextKey{}).(bool)
	return v
}

// SocketPath is deterministic and machine-local, including with a long cache root.
func (p *Project) SocketPath() (string, error) {
	path := filepath.Join(p.Cache, "server.sock")
	if len([]byte(path)) < 104 {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(home))
	root := os.TempDir()
	if runtime.GOOS != "windows" {
		root = "/tmp"
	}
	path = filepath.Join(root, p.rt.cfg.Identity.SocketDirPrefix+"-"+hex.EncodeToString(sum[:8]), p.Key+".sock")
	if len([]byte(path)) >= 104 {
		return "", errors.New("no short socket path available; use serve --tcp-only")
	}
	return path, nil
}

func listenSocket(p *Project) (net.Listener, error) {
	path, err := p.SocketPath()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) || !ownedByCurrentUser(info) {
		return nil, fmt.Errorf("socket directory must be private and owned by this user: %s", dir)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace a non-socket at %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on local socket: %w; use serve --tcp-only if sockets are unavailable", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0600); err != nil {
			ln.Close()
			return nil, err
		}
	}
	return ln, nil
}

func socketHTTPClient(path string, timeout time.Duration) *http.Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// LocalHTTPClient selects a socket when present. A stale socket never falls back
// to an unrelated TCP service. TCP is accepted only after verifying identity.
func LocalHTTPClient(p *Project, timeout time.Duration) (*http.Client, error) {
	path, err := p.SocketPath()
	if err == nil {
		if _, statErr := os.Lstat(path); statErr == nil {
			return socketHTTPClient(path, timeout), nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
	}
	i, err := tcpHealth(p)
	if err != nil {
		return nil, err
	}
	if i.Key != p.Key || (p.Config.Instance != "" && i.Instance != p.Config.Instance) {
		return nil, errors.New("TCP endpoint belongs to another knowledge base")
	}
	if i.Socket != "" {
		return nil, errors.New("server advertises a socket that is missing; restart it or use explicit TCP mode")
	}
	return &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// EnableTCP enables the reader listener without restarting the database server.
func EnableTCP(p *Project) error {
	i, err := Health(p)
	if err != nil {
		return err
	}
	if i.TCP || i.Socket == "" {
		return nil
	} // older server or explicit TCP mode
	_, err = LocalCall(p, "/api/bundle/enable-tcp", map[string]any{})
	return err
}

// removeStaleSocket is called under the project lock when switching to TCP-only.
// A crashed socket must not conceal the explicit TCP listener from local clients.
func removeStaleSocket(p *Project) error {
	path, err := p.SocketPath()
	if err != nil {
		return nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !dir.IsDir() || !ownedByCurrentUser(dir) || (runtime.GOOS != "windows" && dir.Mode().Perm()&0077 != 0) {
		return errors.New("cannot clean socket in an untrusted directory")
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace a non-socket at %s", path)
	}
	return os.Remove(path)
}
