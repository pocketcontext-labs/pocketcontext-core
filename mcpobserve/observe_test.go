package mcpobserve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic sink failure") }

func TestMetadataOnlyAndRequestID(t *testing.T) {
	var out bytes.Buffer
	ctx, id := WithRequest(WithWriter(context.Background(), &out), testPolicy, "knowledge.example.com", "test-revision")
	_, next := WithRequest(ctx, testPolicy, "knowledge.example.com", "test-revision")
	if len(id) != 32 || id == next {
		t.Fatal("request ID must be fresh random server identifier")
	}
	Emit(ctx, Event{Event: "mcp_request", Method: "secret-method", Tool: "secret-tool", Outcome: "tool_error", Reason: "secret-error", APIRoute: "/api/files/sources/private/secret-file?token=secret", DurationMS: 5})
	line := out.String()
	if strings.Contains(line, "secret") {
		t.Fatalf("unclassified value leaked: %s", line)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["request_id"] != id || got["domain"] != "knowledge.example.com" || got["reason"] != "unknown" {
		t.Fatalf("bad metadata: %v", got)
	}
	Emit(WithWriter(ctx, failedWriter{}), Event{Event: "mcp_request", Outcome: "success"})
}
func TestConcurrentJSONLines(t *testing.T) {
	var out bytes.Buffer
	ctx, _ := WithRequest(WithWriter(context.Background(), &out), testPolicy, "knowledge.example.com", "test")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			Emit(ctx, Event{Event: "mcp_request", Method: "tools/call", Tool: "query", Outcome: "success"})
		}()
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 50 {
		t.Fatal(len(lines))
	}
	for _, line := range lines {
		var v map[string]any
		if json.Unmarshal([]byte(line), &v) != nil {
			t.Fatal("interleaved JSON")
		}
	}
}

var testPolicy = Policy{
	Tools:     []string{"note_read", "note_write"},
	APIRoutes: []string{"/api/collections/{collection}/records"},
}

// Without a matching policy a request context classifies names as unknown.
func TestEmitAllowlistComesFromPolicy(t *testing.T) {
	var out bytes.Buffer
	ctx, _ := WithRequest(WithWriter(context.Background(), &out), Policy{}, "example.com", "rev")
	Emit(ctx, Event{Event: "mcp_request", Tool: "note_read", Outcome: "success", APIRoute: "/api/collections/{collection}/records"})
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["tool"] != "unknown" || got["api_route"] != "unknown" {
		t.Fatalf("no-policy classification: %v", got)
	}
	out.Reset()
	ctx, _ = WithRequest(WithWriter(context.Background(), &out), testPolicy, "example.com", "rev")
	Emit(ctx, Event{Event: "mcp_request", Tool: "note_read", Outcome: "success", APIRoute: "/mcp"})
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["tool"] != "note_read" || got["api_route"] != "/mcp" {
		t.Fatalf("policy classification: %v", got)
	}
}
