package appserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

// Instance is what /api/bundle/instance reports.
type Instance struct {
	PublicURL      string `json:"publicURL,omitempty"`
	Hosted         bool   `json:"hosted,omitempty"`
	MCPURL         string `json:"mcpURL,omitempty"`
	App            string `json:"app"`
	Version        string `json:"version"`
	Instance       string `json:"instance"`
	Key            string `json:"key"`
	Name           string `json:"name"`
	Socket         string `json:"socket,omitempty"`
	TCP            bool   `json:"tcp"`
	Headless       bool   `json:"headless"`
	Port           int    `json:"port"`
	DatabaseFormat int    `json:"databaseFormat,omitempty"`
}

// CheckServerCompatibility prevents a client from silently adopting a running
// server from a different release. Health, Running and Stop deliberately remain
// usable across versions so a mismatch can be diagnosed and shut down cleanly.
// A zero format is an older server that did not advertise its storage contract.
func CheckServerCompatibility(p *Project, i *Instance) error {
	version := p.rt.cfg.Version
	if slices.Contains(p.rt.cfg.Identity.LegacyAppIDs, i.App) {
		return fmt.Errorf("running server is an earlier %s release (%s); stop it, then restart with this release", p.rt.cfg.Identity.DisplayName, i.Version)
	}
	if i.Version != version {
		return fmt.Errorf("running server version %q differs from this binary %q; stop it cleanly with its own binary, then restart with the selected release", i.Version, version)
	}
	if i.DatabaseFormat != 0 && i.DatabaseFormat != DatabaseFormat {
		return fmt.Errorf("running server database format %d is unsupported; this binary supports format %d", i.DatabaseFormat, DatabaseFormat)
	}
	return nil
}

func compatibleRunning(p *Project) error {
	i, err := Health(p)
	if err != nil {
		return err
	}
	if i.Key != p.Key || (p.Config.Instance != "" && i.Instance != p.Config.Instance) {
		return errors.New("running server identity changed while checking its version; retry after verifying the selected project")
	}
	return CheckServerCompatibility(p, i)
}

var quick = &http.Client{Timeout: 2 * time.Second}

// errNotRunning means nothing answers on the project's port.
var errNotRunning = errors.New("not running")

// knownApp reports whether the app id answering on a local endpoint is this
// application or one of its earlier ids. A legacy id may be probed and stopped
// but never adopted: CheckServerCompatibility refuses it.
func knownApp(p *Project, app string) bool {
	id := p.rt.cfg.Identity
	return app == id.AppID || slices.Contains(id.LegacyAppIDs, app)
}

// Health asks the project's port which server answers.
func Health(p *Project) (*Instance, error) {
	path, err := p.SocketPath()
	if err == nil {
		if _, statErr := os.Lstat(path); statErr == nil {
			client := socketHTTPClient(path, 2*time.Second)
			defer client.CloseIdleConnections()
			resp, err := client.Get(p.URL() + "/api/bundle/instance")
			if err != nil {
				return nil, errNotRunning
			}
			defer resp.Body.Close()
			var i Instance
			if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&i) != nil || !knownApp(p, i.App) {
				return nil, errors.New("unexpected local socket server")
			}
			return &i, nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
	}
	return tcpHealth(p)
}

func tcpHealth(p *Project) (*Instance, error) {
	resp, err := quick.Get(p.URL() + "/api/bundle/instance")
	if err != nil {
		return nil, errNotRunning
	}
	defer resp.Body.Close()
	var i Instance
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&i) != nil || !knownApp(p, i.App) {
		return nil, fmt.Errorf("port %d is used by another program; set a different \"port\" in %s", p.Config.Port, p.ConfigPath)
	}
	// Legacy servers have no transport fields but answered this TCP request.
	if i.Socket == "" {
		i.TCP = true
		i.Headless = false
		i.Port = p.Config.Port
	}
	return &i, nil
}

// Running reports whether this project's own server answers.
func Running(p *Project) (bool, error) {
	i, err := Health(p)
	if errors.Is(err, errNotRunning) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if i.Key != p.Key || (p.Config.Instance != "" && i.Instance != p.Config.Instance) {
		return false, fmt.Errorf("port %d is used by another %s database; set a different \"port\" in %s", p.Config.Port, p.rt.cfg.Identity.DisplayName, p.ConfigPath)
	}
	return true, nil
}

// StartOptions control EnsureRunning.
type StartOptions struct {
	TakeOver bool
	TCP      bool
}

// EnsureRunning starts the server in the background unless it already runs,
// then waits until it answers. It is safe to call before every command.
func EnsureRunning(p *Project, opts StartOptions) error {
	return EnsureRunningContext(context.Background(), p, opts)
}

// EnsureRunningContext allows a caller to cancel the startup wait. A server
// already launched remains running independently, just as after successful start.
func EnsureRunningContext(ctx context.Context, p *Project, opts StartOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ok, err := runningForStart(p, opts)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if ok {
		return compatibleRunning(p)
	}
	if err != nil {
		return err
	}
	if err := os.MkdirAll(p.Cache, 0700); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logFile, err := os.OpenFile(p.LogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	start, _ := logFile.Seek(0, io.SeekEnd)
	args := []string{"serve", "--db", p.DB}
	if opts.TCP {
		args = append(args, "--tcp-only")
	} else {
		args = append(args, "--headless")
	}
	if opts.TakeOver {
		args = append(args, "--take-over")
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.Dir = p.Cache
	detach(cmd)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-exited:
			return fmt.Errorf("the %s server stopped during start: %s (log: %s)", p.rt.cfg.Identity.DisplayName, lastLines(p.LogFile(), start), p.LogFile())
		case <-time.After(200 * time.Millisecond):
		}
		if err := p.loadConfig(); err != nil { // serve may have just created the instance ID
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if ok, err := runningForStart(p, opts); ok {
			_ = cmd.Process.Release()
			return compatibleRunning(p)
		} else if err != nil {
			return err
		}
	}
	return fmt.Errorf("the %s server did not answer within 60 seconds; see %s", p.rt.cfg.Identity.DisplayName, p.LogFile())
}

// runningForStart allows an unrelated TCP listener during headless startup.
// Health may fall back to TCP just before the child creates its socket. If the
// socket appeared during that request, recheck it instead of returning the stale
// TCP error. The second check still validates socket identity and access.
func runningForStart(p *Project, opts StartOptions) (bool, error) {
	running, err := Running(p)
	if err == nil || opts.TCP {
		return running, err
	}
	if socketAbsent(p) {
		return false, nil
	}
	return Running(p)
}

// socketAbsent allows headless startup despite an unrelated TCP service, but
// never suppresses errors from an existing or inaccessible socket endpoint.
func socketAbsent(p *Project) bool {
	path, err := p.SocketPath()
	if err != nil {
		return false
	}
	_, err = os.Lstat(path)
	return errors.Is(err, os.ErrNotExist)
}

func lastLines(path string, from int64) string {
	data, err := os.ReadFile(path)
	if err != nil || int64(len(data)) < from {
		return "unknown error"
	}
	lines := strings.Split(strings.TrimSpace(string(data[from:])), "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	return strings.Join(lines, " | ")
}

// ReadKey returns the running server's local key.
func ReadKey(p *Project) (string, error) {
	data, err := os.ReadFile(p.KeyFile())
	if err != nil {
		return "", errors.New("the local server key is missing; is the server running for this database?")
	}
	return strings.TrimSpace(string(data)), nil
}

// LocalCall sends a key-authenticated request to the running server.
func LocalCall(p *Project, path string, body any) (map[string]any, error) {
	// Management operations can mutate settings or issue credentials without
	// going through EnsureRunning. Keep only shutdown available across releases.
	if path != "/api/bundle/stop" {
		if err := compatibleRunning(p); err != nil {
			return nil, err
		}
	}
	key, err := ReadKey(p)
	if err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", p.URL()+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(p.rt.cfg.Identity.LocalKeyHeader, key)
	client, err := LocalHTTPClient(p, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var data map[string]any
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data)
	if resp.StatusCode != 200 {
		msg, _ := data["message"].(string)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}
	return data, nil
}

// Stop asks the server to write back and exit, then waits until it has.
func Stop(p *Project) error {
	ok, err := Running(p)
	if err != nil || !ok {
		return err
	}
	if _, err := LocalCall(p, "/api/bundle/stop", map[string]any{}); err != nil {
		return err
	}
	lock := p.Cache + string(os.PathSeparator) + "server.lock"
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if f, err := os.OpenFile(lock, os.O_RDWR, 0600); err == nil {
			if lockFile(f) == nil { // the server released its lock: it has exited
				f.Close()
				return nil
			}
			f.Close()
		}
	}
	return errors.New("the server did not stop within 30 seconds")
}

// OpenBrowser requests browser dispatch. Success does not prove a browser opened.
func OpenBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return dispatchBrowser(exec.Command("open", url), 750*time.Millisecond)
	case "windows":
		return dispatchBrowser(exec.Command("rundll32", "url.dll,FileProtocolHandler", url), 750*time.Millisecond)
	default:
		return dispatchBrowser(exec.Command("xdg-open", url), 750*time.Millisecond)
	}
}

// Recover resolves an interrupted run; the server must not be running.
func Recover(p *Project, keepLocal bool) error {
	if ok, err := Running(p); err != nil || ok {
		if ok {
			return errors.New("stop the server first")
		}
		return err
	}
	return (&Store{p: p}).Recover(keepLocal)
}

// Conflicts lists copies that preserve changes made while another computer
// replaced the synced database. They need the user's review.
func Conflicts(p *Project) []string {
	matches, _ := filepath.Glob(p.DB + ".conflict-*.db")
	return matches
}
