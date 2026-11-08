// Package appserver runs one application as one local binary: a project is a
// SQLite file, its storage folder and an optional configuration file, all of
// which may live in a cloud-synced folder. Everything else stays in a per-machine
// cache. Everything product-specific comes from the Config given to New.
package appserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/pocketcontext-labs/pocketcontext-core/atomicfile"
)

// ProjectConfig is the optional configuration file beside the database. It is
// synced with the project, so it never contains credentials or machine-specific
// paths. Identity.ConfigFile names it.
type ProjectConfig struct {
	Name     string `json:"name,omitempty"`
	Port     int    `json:"port"`
	Instance string `json:"instance,omitempty"`
}

// Project is one application database and the paths derived from it.
type Project struct {
	rt         *Runtime
	DB         string // absolute path of the synced database file
	Dir        string // folder holding the database, storage/ and the configuration file
	ConfigPath string
	Cache      string // private per-machine cache for this database
	Key        string // stable per-machine identifier of this database path
	LeaseHost  string // runtime-only stable identity for an exclusively locked hosted volume
	Config     ProjectConfig
}

// Resolve finds the project from an explicit path, the <EnvPrefix>_DB variable,
// or the database file beside the executable, in that order. A directory
// selects its database file.
func (rt *Runtime) Resolve(db string) (*Project, error) {
	id := rt.cfg.Identity
	if db == "" {
		db = os.Getenv(id.EnvPrefix + "_DB")
	}
	if db == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, errors.New("cannot locate the executable; pass --db")
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		db = filepath.Join(filepath.Dir(exe), id.DatabaseFile)
	}
	abs, err := filepath.Abs(db)
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(abs); err == nil && info.IsDir() {
		abs = filepath.Join(abs, id.DatabaseFile)
	}
	p := &Project{rt: rt, DB: abs, Dir: filepath.Dir(abs)}
	p.ConfigPath = filepath.Join(p.Dir, id.ConfigFile)
	identity := abs
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		identity = strings.ToLower(identity) // case-insensitive filesystems
	}
	sum := sha256.Sum256([]byte(identity))
	p.Key = hex.EncodeToString(sum[:8])
	base, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("no user cache directory: %w", err)
	}
	p.Cache = filepath.Join(base, id.CacheRoot, p.Key)
	p.Config = ProjectConfig{Port: id.DefaultPort}
	if err := p.loadConfig(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Project) loadConfig() error {
	data, err := os.ReadFile(p.ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var c ProjectConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return fmt.Errorf("%s: %w", p.ConfigPath, err)
	}
	if c.Port == 0 {
		c.Port = p.rt.cfg.Identity.DefaultPort
	}
	if c.Port < 1024 || c.Port > 65535 {
		return fmt.Errorf("%s: port must be 1024-65535", p.ConfigPath)
	}
	p.Config = c
	return nil
}

// SaveConfig writes the project configuration file atomically.
func (p *Project) SaveConfig() error {
	data, err := json.MarshalIndent(p.Config, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteAtomic(p.ConfigPath, append(data, '\n'), 0644)
}

// EnsureInstance gives the project a stable identifier shared by every computer.
func (p *Project) EnsureInstance() error {
	if p.Config.Instance != "" {
		return nil
	}
	p.Config.Instance = atomicfile.RandomHex(16)
	return p.SaveConfig()
}

func (p *Project) URL() string       { return fmt.Sprintf("http://127.0.0.1:%d", p.Config.Port) }
func (p *Project) LiveDir() string   { return filepath.Join(p.Cache, "live") }
func (p *Project) KeyFile() string   { return filepath.Join(p.Cache, "local.key") }
func (p *Project) LogFile() string   { return filepath.Join(p.Cache, "server.log") }
func (p *Project) LeaseFile() string { return p.DB + ".lease" }
func (p *Project) StorageDir() string {
	return filepath.Join(p.Dir, "storage")
}
