//go:build linux

package appserver

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxDisplaySignals(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "wayland-test")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if !linuxDisplayAvailable("", "wayland-test", root) {
		t.Fatal("accessible Wayland socket ignored")
	}
	if linuxDisplayAvailable(":65535.0", "", "") {
		t.Fatal("stale X11 socket accepted")
	}
	if linuxDisplayAvailable("", "missing", root) {
		t.Fatal("missing socket accepted")
	}
	if linuxDisplayAvailable("localhost:10.0", "", "") {
		t.Fatal("forwarded X11 inferred as local desktop")
	}
	if linuxDisplayAvailable(":../../private", "", "") {
		t.Fatal("invalid display path accepted")
	}
	if linuxDisplayAvailable("", "relative", "relative") {
		t.Fatal("relative runtime directory accepted")
	}
}

func TestDesktopExecutableIsDataNotShell(t *testing.T) {
	for _, tc := range []struct{ content, want string }{
		{"[Desktop Entry]\nExec=firefox %u\n", "firefox"},
		{"[Desktop Entry]\nExec=\"/path with spaces/browser\" %u\n", "/path with spaces/browser"},
		{"[Desktop Entry]\nExec=missing %u\nTryExec=browser\n", "missing"},
		{"[Desktop Entry]\nExec=env MISSING=yes browser %u\n", ""},
		{"[Desktop Entry]\nExec=/bin/sh -c browser\n", ""},
		{"[Desktop Entry]\nExec=browser %u\nHidden=true\n", ""},
		{"[Other]\nExec=browser\n", ""},
		{"[Desktop Entry]\nExec=\"unterminated\n", ""},
		{"[Desktop Entry]\nExec=%u\n", ""},
	} {
		if got := desktopExecutable(tc.content); got != tc.want {
			t.Fatalf("got %q, want %q", got, tc.want)
		}
	}
}

func TestLinuxDetectionDoesNotLaunchBrowser(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "DISPLAY", "WAYLAND_DISPLAY"} {
		t.Setenv(key, "")
	}
	t.Setenv("PATH", root)
	t.Setenv("XDG_RUNTIME_DIR", root)
	t.Setenv("XDG_DATA_HOME", root)
	t.Setenv("XDG_DATA_DIRS", root)
	if e := ReaderEnvironment(); e.Session != "headless" || e.CanOpen() {
		t.Fatalf("headless: %+v", e)
	}
	path := filepath.Join(root, "wayland-test")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("WAYLAND_DISPLAY", "wayland-test")
	if e := ReaderEnvironment(); e.Session != "desktop" || e.Browser != "unavailable" {
		t.Fatalf("missing opener: %+v", e)
	}
	for name, body := range map[string]string{
		"xdg-open":     "#!/bin/sh\nexit 99\n",
		"xdg-settings": "#!/bin/sh\nprintf 'browser.desktop\\n'\n",
		"browser":      "#!/bin/sh\nexit 99\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "applications"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "applications", "browser.desktop"), []byte("[Desktop Entry]\nExec=browser %u\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if e := ReaderEnvironment(); !e.CanOpen() {
		t.Fatalf("known handler: %+v", e)
	}
	os.Remove(filepath.Join(root, "browser"))
	if e := ReaderEnvironment(); e.Browser != "unavailable" || e.CanOpen() {
		t.Fatalf("missing handler executable: %+v", e)
	}
}
