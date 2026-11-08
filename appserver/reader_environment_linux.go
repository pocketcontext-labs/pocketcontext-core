//go:build linux

package appserver

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func nativeReaderEnvironment() ReaderEnvironmentInfo {
	display, wayland := os.Getenv("DISPLAY"), os.Getenv("WAYLAND_DISPLAY")
	if display == "" && wayland == "" {
		return ReaderEnvironmentInfo{"headless", "unknown", "No graphical display is configured for this session"}
	}
	if !linuxDisplayAvailable(display, wayland, os.Getenv("XDG_RUNTIME_DIR")) {
		return ReaderEnvironmentInfo{"unknown", "unknown", "A display is configured but access to it could not be established"}
	}
	if _, err := exec.LookPath("xdg-open"); err != nil {
		return ReaderEnvironmentInfo{"desktop", "unavailable", "A desktop display is accessible but its browser launcher is unavailable"}
	}
	// xdg-settings is an optional read-only association probe, never a runtime
	// requirement. No shell is used, and an absent or inconclusive probe is unknown.
	settings, err := exec.LookPath("xdg-settings")
	if err != nil {
		return ReaderEnvironmentInfo{"desktop", "unknown", "Desktop detected; the default HTTP browser could not be determined"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, settings, "get", "default-web-browser")
	cmd.WaitDelay = 200 * time.Millisecond
	data, err := cmd.Output()
	if err != nil {
		return ReaderEnvironmentInfo{"desktop", "unknown", "Desktop detected; the default HTTP browser could not be determined"}
	}
	id := strings.TrimSpace(string(data))
	if id == "" {
		return ReaderEnvironmentInfo{"desktop", "unavailable", "Desktop detected but no default browser is configured"}
	}
	if filepath.Base(id) != id || !strings.HasSuffix(id, ".desktop") {
		return ReaderEnvironmentInfo{"desktop", "unknown", "Desktop detected; its browser association is not recognized"}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ReaderEnvironmentInfo{"desktop", "unknown", "Desktop detected; its browser association could not be checked"}
	}
	dataHome := os.Getenv("XDG_DATA_HOME")
	if !filepath.IsAbs(dataHome) {
		dataHome = filepath.Join(home, ".local", "share")
	}
	dirs := []string{dataHome}
	dataDirs := os.Getenv("XDG_DATA_DIRS")
	if dataDirs == "" {
		dataDirs = "/usr/local/share:/usr/share"
	}
	for _, dir := range filepath.SplitList(dataDirs) {
		if filepath.IsAbs(dir) {
			dirs = append(dirs, dir)
		}
	}
	for _, dir := range dirs {
		data, err := os.ReadFile(filepath.Join(dir, "applications", id))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			break
		}
		executable := desktopExecutable(string(data))
		if executable == "" {
			break
		}
		if _, err := exec.LookPath(executable); err == nil {
			return ReaderEnvironmentInfo{"desktop", "available", "Desktop display and default browser handler detected; opening is not yet verified"}
		}
		return ReaderEnvironmentInfo{"desktop", "unavailable", "The configured default browser executable is unavailable"}
	}
	return ReaderEnvironmentInfo{"desktop", "unknown", "Desktop detected; the configured browser could not be verified"}
}

func linuxDisplayAvailable(display, wayland, runtimeDir string) bool {
	if wayland != "" {
		path := wayland
		if !filepath.IsAbs(path) && filepath.IsAbs(runtimeDir) && filepath.Base(path) == path {
			path = filepath.Join(runtimeDir, path)
		}
		if filepath.IsAbs(path) && accessibleDisplaySocket(path) {
			return true
		}
	}
	// Never probe arbitrary DISPLAY hosts or ports. A non-local display is
	// inconclusive, even when no SSH variable survived a terminal multiplexer.
	if strings.HasPrefix(display, ":") {
		number := strings.SplitN(strings.TrimPrefix(display, ":"), ".", 2)[0]
		n, err := strconv.Atoi(number)
		if err == nil && n >= 0 && n <= 65535 && strconv.Itoa(n) == number {
			return accessibleDisplaySocket(filepath.Join("/tmp/.X11-unix", "X"+number))
		}
	}
	return false
}

func accessibleDisplaySocket(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return false
	}
	conn, err := net.DialTimeout("unix", path, 150*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// desktopExecutable extracts only the executable token, never runs desktop-file
// commands or expands placeholders. Unsupported quoting stays inconclusive.
func desktopExecutable(content string) string {
	section, executable := "", ""
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if section != "[Desktop Entry]" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "Hidden":
			if value == "true" {
				return ""
			}
		case "Exec":
			executable = strings.TrimSpace(value)
		}
	}
	if strings.HasPrefix(executable, "\"") {
		end := strings.Index(executable[1:], "\"")
		if end < 0 {
			return ""
		}
		token, err := strconv.Unquote(executable[:end+2])
		if err != nil {
			return ""
		}
		return directBrowserExecutable(token)
	}
	fields := strings.Fields(executable)
	if len(fields) == 0 || strings.ContainsAny(fields[0], "\\%'") {
		return ""
	}
	return directBrowserExecutable(fields[0])
}

// Wrapper commands do not establish that their eventual browser exists. Keep
// them unknown rather than interpreting shell syntax, environment assignments,
// container launch commands or custom executable arguments.
func directBrowserExecutable(token string) string {
	switch filepath.Base(token) {
	case "env", "sh", "bash", "dash", "zsh", "fish", "csh", "tcsh", "flatpak", "snap", "gio", "xdg-open":
		return ""
	}
	return token
}
