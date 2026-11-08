// Package appidentity is the value type naming one application built on core.
// It has no defaults and no third-party dependencies: every field is required.
package appidentity

import (
	"errors"
	"fmt"
	"net/mail"
	"reflect"
	"strings"
	"unicode"
)

// Identity holds every name that distinguishes one application from another.
type Identity struct {
	// AppID is the "app" field of /api/bundle/instance and the only value Health
	// treats as this application. LegacyAppIDs may be probed and stopped, never adopted.
	AppID        string
	LegacyAppIDs []string

	DisplayName string // human messages, login title
	Command     string // command named in error hints

	SkillName    string // installed skill directory name
	Marker       string // marker file written into skill directories
	RouterMarker string // marker file for the router skill

	RegistryNamespace string // <UserConfigDir>/<ns>/profiles.json
	CacheRoot         string // <UserCacheDir>/<root>/<key>

	SocketHost      string // Host accepted only on the private socket
	SocketDirPrefix string // fallback /tmp/<prefix>-<hash of home>/

	DefaultPort  int
	DatabaseFile string
	ConfigFile   string

	EnvPrefix         string // used as EnvPrefix + "_DB", "_MCP_REDIRECT_EXCEPTIONS", ...
	LocalKeyHeader    string // local key request header, stripped on public listeners
	LocalAccountEmail string // the one account's persisted sign-in identity
	ReaderStorageKey  string // browser localStorage key for the reader session
	HookGlobal        string // JS binding name in hooks and migrations
}

// Validate fails closed: an empty or unsafe field is an error. Nothing defaults.
func (id Identity) Validate() error {
	v := reflect.ValueOf(id)
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		name := t.Field(i).Name
		if v.Field(i).Kind() != reflect.String {
			continue
		}
		value := v.Field(i).String()
		switch name {
		case "LocalKeyHeader":
			if !validHTTPToken(value) {
				return fmt.Errorf("identity %s must be an HTTP token", name)
			}
		case "LocalAccountEmail":
			if parsed, err := mail.ParseAddress(value); err != nil || parsed.Address != value {
				return fmt.Errorf("identity %s must be a plain address", name)
			}
		default:
			if value == "" || value == "." || value == ".." || strings.ContainsAny(value, `/\`) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
				return fmt.Errorf("identity %s must be non-empty and free of path separators and control characters", name)
			}
		}
	}
	if id.DefaultPort < 1024 || id.DefaultPort > 65535 {
		return errors.New("identity DefaultPort must be 1024-65535")
	}
	for _, legacy := range id.LegacyAppIDs {
		if legacy == "" || legacy == id.AppID {
			return errors.New("identity LegacyAppIDs entries must be non-empty and differ from AppID")
		}
	}
	return nil
}

func validHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c >= 127 || c <= 32 || strings.ContainsRune(`()<>@,;:\"/[]?={}`, c) {
			return false
		}
	}
	return true
}
