package appserver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"

	"ganigeorgiev.com/pocketbase/pocketbase/plugins/jsvm"
	"github.com/dop251/goja"
)

// hooksConfig loads pb_hooks and pb_migrations from appDir with the application's
// bindings. typesDir receives PocketBase's types.d.ts; never the project.
func hooksConfig(rt *Runtime, appDir, typesDir string) jsvm.Config {
	return jsvm.Config{
		HooksDir:      filepath.Join(appDir, "pb_hooks"),
		MigrationsDir: filepath.Join(appDir, "pb_migrations"),
		TypesDir:      typesDir,
		HooksWatch:    false,
		OnInit:        func(vm *goja.Runtime) { registerHookBindings(rt, vm) },
	}
}

// registerHookBindings adds the HookGlobal object to every hook and migration
// runtime. sha256 always comes from core; a product binding can never replace it.
// Hooks must not start external processes (stock Windows has no sha256sum),
// so anything they cannot do in JavaScript is provided here in Go.
func registerHookBindings(rt *Runtime, vm *goja.Runtime) {
	bindings := map[string]any{}
	if rt.cfg.Hooks.Bindings != nil {
		for name, value := range rt.cfg.Hooks.Bindings(vm) {
			bindings[name] = value
		}
	}
	// sha256(reader) streams the raw bytes of reader (for example a
	// filesystem reader of an original) and returns the lowercase hex digest.
	bindings["sha256"] = readerSHA256
	vm.Set(rt.cfg.Identity.HookGlobal, bindings)
}

func readerSHA256(r io.Reader) (string, error) {
	if r == nil {
		return "", errors.New("sha256: no reader")
	}
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
