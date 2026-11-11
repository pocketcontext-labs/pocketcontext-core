// Package profiles stores private, machine-local project registrations.
package profiles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/pocketcontext-labs/pocketcontext-core/atomicfile"
)

const Format = 1

type Entry struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Instance      string `json:"instance"`
	ServerName    string `json:"serverName,omitempty"`
	DB            string `json:"db,omitempty"`
	URL           string `json:"url,omitempty"`
	Binary        string `json:"binary"`
	Version       string `json:"version"`
	ServerVersion string `json:"serverVersion,omitempty"`
	Skill         string `json:"skill"`
}
type Registry struct {
	Format   int     `json:"format"`
	Default  string  `json:"default,omitempty"`
	Profiles []Entry `json:"profiles"`
}

// Store is the private registry of one application, named by its namespace.
type Store struct{ namespace string }

// New returns the registry stored under <UserConfigDir>/<namespace>.
func New(namespace string) *Store { return &Store{namespace: namespace} }

func (s *Store) Path() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, s.namespace, "profiles.json"), nil
}
func (s *Store) SkillDir(instance string) (string, error) {
	p, err := s.Path()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(p), "profiles", ID(instance), "skill"), nil
}
func ID(instance string) string {
	sum := sha256.Sum256([]byte(instance))
	return hex.EncodeToString(sum[:16])
}
func ValidateName(name string) error {
	if name == "" || len(name) > 80 || strings.TrimSpace(name) != name {
		return errors.New("name must contain 1–80 bytes without surrounding whitespace")
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '/' || r == '\\' {
			return errors.New("name must not contain control characters or path separators")
		}
	}
	if name == "." || name == ".." {
		return errors.New("invalid profile name")
	}
	return nil
}
func (s *Store) Read() (*Registry, error) {
	path, err := s.Path()
	if err != nil {
		return nil, err
	}
	return read(path)
}
func read(path string) (*Registry, error) {
	r := &Registry{Format: Format, Profiles: []Entry{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, r); err != nil {
		return nil, fmt.Errorf("invalid profile registry: %w", err)
	}
	if r.Format != Format {
		return nil, fmt.Errorf("unsupported registry format %d; use a compatible binary", r.Format)
	}
	names := map[string]bool{}
	ids := map[string]bool{}
	for _, e := range r.Profiles {
		if err := Validate(e); err != nil {
			return nil, err
		}
		if names[e.Name] || ids[e.ID] {
			return nil, errors.New("registry has duplicate names or project identities")
		}
		names[e.Name] = true
		ids[e.ID] = true
	}
	if r.Default != "" && !names[r.Default] {
		return nil, errors.New("registry default does not name a registered project")
	}
	return r, nil
}
func Validate(e Entry) error {
	if err := ValidateName(e.Name); err != nil {
		return err
	}
	if e.Instance == "" || e.ID != ID(e.Instance) {
		return errors.New("profile needs a verified project instance")
	}
	if (e.DB == "") == (e.URL == "") {
		return errors.New("profile needs exactly one database path or URL")
	}
	if e.DB != "" && !filepath.IsAbs(e.DB) {
		return errors.New("profile database path must be absolute")
	}
	if e.URL != "" {
		u, err := url.Parse(e.URL)
		if err != nil {
			return errors.New("invalid profile URL")
		}
		n, err := strconv.Atoi(u.Port())
		if err != nil || n < 1 || n > 65535 || u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("profile URL must be a loopback HTTP URL with an explicit port")
		}
	}
	if !filepath.IsAbs(e.Binary) || !filepath.IsAbs(e.Skill) || e.Version == "" {
		return errors.New("profile needs absolute binary and skill paths and a binary version")
	}
	return nil
}

// Change holds an OS lock across the read-modify-write transaction. Crash releases it.
func (s *Store) Change(fn func(*Registry) error) error {
	path, err := s.Path()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = lockFile(lock)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("profile registry is busy: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	r, err := read(path)
	if err != nil {
		return err
	}
	if err = fn(r); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.WriteAtomic(path, append(b, '\n'), 0600)
}
func (r *Registry) Find(name string) (Entry, error) {
	if name == "" {
		name = r.Default
	}
	for _, e := range r.Profiles {
		if e.Name == name {
			return e, nil
		}
	}
	return Entry{}, fmt.Errorf("profile %q not found; name a profile or set a default", name)
}

// Put allows an explicit update only for the same stable project identity.
func (s *Store) Put(e Entry, update bool) error {
	if err := Validate(e); err != nil {
		return err
	}
	return s.Change(func(r *Registry) error {
		for _, old := range r.Profiles {
			if old.Name == e.Name && old.Instance != e.Instance {
				return fmt.Errorf("name %q belongs to another project", e.Name)
			}
		}
		for i, old := range r.Profiles {
			if old.Instance == e.Instance {
				if !update {
					return fmt.Errorf("project already registered as %q; use profile update", old.Name)
				}
				if r.Default == old.Name {
					r.Default = e.Name
				}
				r.Profiles[i] = e
				return nil
			}
		}
		r.Profiles = append(r.Profiles, e)
		return nil
	})
}
func (s *Store) Remove(name string) error {
	return s.Change(func(r *Registry) error {
		for i, e := range r.Profiles {
			if e.Name == name {
				r.Profiles = append(r.Profiles[:i], r.Profiles[i+1:]...)
				if r.Default == name {
					r.Default = ""
				}
				return nil
			}
		}
		return fmt.Errorf("profile %q not found", name)
	})
}
func (s *Store) Default(name string) error {
	return s.Change(func(r *Registry) error {
		if name != "" {
			if _, err := r.Find(name); err != nil {
				return err
			}
		}
		r.Default = name
		return nil
	})
}
