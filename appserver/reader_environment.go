package appserver

import (
	"errors"
	"os"
	"os/exec"
	"time"
)

// ReaderEnvironmentInfo describes this process's session, not the whole machine.
// It is advisory: an agent's explicit knowledge of remote execution takes priority.
// No environment values, user names, browser paths or credentials are returned.
type ReaderEnvironmentInfo struct {
	Session string `json:"session"`
	Browser string `json:"browser"`
	Reason  string `json:"reason"`
}

// CanOpen reports whether automatic browser dispatch has enough local evidence.
// It does not promise that a window will open or that the user can see it.
func (e ReaderEnvironmentInfo) CanOpen() bool {
	return e.Session == "desktop" && e.Browser == "available"
}

// ReaderEnvironment inspects session and browser associations without starting a
// browser, a server or a tunnel. A terminal is deliberately not a desktop signal.
func ReaderEnvironment() ReaderEnvironmentInfo {
	return inspectReaderEnvironment(os.Getenv, nativeReaderEnvironment)
}

func inspectReaderEnvironment(getenv func(string) string, native func() ReaderEnvironmentInfo) ReaderEnvironmentInfo {
	for _, name := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		if getenv(name) != "" {
			return ReaderEnvironmentInfo{"ssh", "unknown", "SSH session detected; use the reader on your own computer after connecting it"}
		}
	}
	return native()
}

// dispatchBrowser waits briefly for immediate launcher failures. A helper may
// keep running with its browser, so a successful Start followed by this bounded
// wait means only that dispatch was requested, never that a browser opened.
// Wait always reaps a child when it exits; output is suppressed because it can
// contain a credential-bearing URL. We do not kill a browser after a timeout.
func dispatchBrowser(cmd *exec.Cmd, grace time.Duration) error {
	err, _ := dispatchBrowserTracked(cmd, grace)
	return err
}

// The completion signal lets tests await their synthetic helper's actual reap.
func dispatchBrowserTracked(cmd *exec.Cmd, grace time.Duration) (error, <-chan struct{}) {
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Start(); err != nil {
		return errors.New("could not start the browser launcher"), nil
	}
	done := make(chan error, 1)
	reaped := make(chan struct{})
	go func() { done <- cmd.Wait(); close(reaped) }()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-done:
		if err != nil {
			return errors.New("the browser launcher failed; open the reader on a connected computer"), reaped
		}
		return nil, reaped
	case <-timer.C:
		return nil, reaped
	}
}
