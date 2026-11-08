package appserver

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestReaderEnvironmentSSHOverridesDesktop(t *testing.T) {
	for _, key := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		t.Run(key, func(t *testing.T) {
			called := false
			got := inspectReaderEnvironment(func(name string) string {
				if name == key {
					return "private-host-address"
				}
				if name == "DISPLAY" {
					return ":0"
				}
				return ""
			}, func() ReaderEnvironmentInfo {
				called = true
				return ReaderEnvironmentInfo{"desktop", "available", "local"}
			})
			if got.Session != "ssh" || got.CanOpen() || called || strings.Contains(got.Reason, "private-host") {
				t.Fatalf("SSH detection consulted desktop or disclosed environment: %+v, probe=%v", got, called)
			}
		})
	}
}

func TestReaderEnvironmentPreservesUnknownAndDoesNotUseTTY(t *testing.T) {
	for _, info := range []ReaderEnvironmentInfo{
		{"unknown", "unknown", "uncertain"},
		{"headless", "unknown", "no display"},
		{"desktop", "unavailable", "no handler"},
		{"desktop", "unknown", "handler uncertain"},
		{"desktop", "available", "detected"},
	} {
		got := inspectReaderEnvironment(func(key string) string {
			if key == "TERM" {
				return "xterm-256color"
			}
			return ""
		}, func() ReaderEnvironmentInfo { return info })
		if got != info || got.CanOpen() != (info.Session == "desktop" && info.Browser == "available") {
			t.Fatalf("incorrect reader policy: %+v", got)
		}
	}
}

func TestBrowserLauncherHelper(t *testing.T) {
	switch os.Getenv("FIXTURE_TEST_BROWSER_HELPER") {
	case "success":
		os.Exit(0)
	case "failure":
		os.Stdout.WriteString("credential-bearing-url")
		os.Stderr.WriteString("credential-bearing-url")
		os.Exit(7)
	case "slow":
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}
}

func TestBrowserDispatchReportsOnlyLauncherOutcome(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "failure", "slow"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(exe, "-test.run=^TestBrowserLauncherHelper$")
			cmd.Env = append(os.Environ(), "FIXTURE_TEST_BROWSER_HELPER="+mode)
			grace := 2 * time.Second
			if mode == "slow" {
				grace = 10 * time.Millisecond
			}
			started := time.Now()
			err, reaped := dispatchBrowserTracked(cmd, grace)
			if reaped != nil {
				t.Cleanup(func() {
					select {
					case <-reaped:
					case <-time.After(5 * time.Second):
						t.Error("synthetic browser helper was not reaped")
					}
				})
			}
			if (err != nil) != (mode == "failure") {
				t.Fatalf("dispatch %s: %v", mode, err)
			}
			if err != nil && strings.Contains(err.Error(), "credential") {
				t.Fatal("launcher output disclosed")
			}
			if mode == "slow" && time.Since(started) > 400*time.Millisecond {
				t.Fatal("dispatch waited for long-running browser")
			}
		})
	}
	if err := dispatchBrowser(exec.Command("/nonexistent/pocketcontext-test-browser"), time.Second); err == nil || strings.Contains(err.Error(), "nonexistent") {
		t.Fatalf("missing launcher error should be generic: %v", err)
	}
}
