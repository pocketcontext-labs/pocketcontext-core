package appserver

import (
	"context"
	"errors"
	"github.com/pocketcontext-labs/pocketcontext-core/atomicfile"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestEnsureRunningCancellationPreventsStartup(t *testing.T) {
	for _, duringHealth := range []bool{false, true} {
		t.Run(strconv.FormatBool(duringHealth), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := &Project{rt: testRT, Cache: filepath.Join(t.TempDir(), "cache"), Key: atomicfile.RandomHex(8)}
			if duringHealth {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					cancel()
					http.Error(w, "unrelated listener", http.StatusNotFound)
				}))
				defer server.Close()
				var err error
				p.Config.Port, err = strconv.Atoi(strings.TrimPrefix(server.URL, "http://127.0.0.1:"))
				if err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			if err := EnsureRunningContext(ctx, p, StartOptions{}); !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation, got %v", err)
			}
			if _, err := os.Stat(p.Cache); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("cancelled startup created cache: %v", err)
			}
		})
	}
}
