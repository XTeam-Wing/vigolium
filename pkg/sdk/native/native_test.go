package native

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/modules/passive/software_version_header"
)

func TestRunURLReturnsJSONMarshalableResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "VigoliumTest/1.2.3")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	cfg := NewConfig(
		WithPassiveModules(software_version_header.New()),
		WithPassive(true),
		WithConcurrency(1),
		WithMaxPerHost(1),
	)

	results, err := cfg.RunURL(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("RunURL() error = %v", err)
	}
	if len(results) == 0 {
		t.Fatal("RunURL() returned no findings")
	}
	if results[0].ModuleID != "software-version-header" {
		t.Fatalf("ModuleID = %q, want software-version-header", results[0].ModuleID)
	}
	if _, err := json.Marshal(results); err != nil {
		t.Fatalf("results are not JSON marshalable: %v", err)
	}
}

func TestRunURLOnResultReceivesReturnedEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "UnitTest/2.4.6")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	var mu sync.Mutex
	var streamed []*Result
	cfg := NewConfig(
		WithPassiveModules(software_version_header.New()),
		WithConcurrency(1),
		WithOnResult(func(r *Result) {
			mu.Lock()
			defer mu.Unlock()
			streamed = append(streamed, r)
		}),
	)

	results, err := cfg.RunURL(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("RunURL() error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(streamed) != len(results) {
		t.Fatalf("streamed %d result(s), returned %d", len(streamed), len(results))
	}
	if len(results) > 0 && streamed[0] != results[0] {
		t.Fatal("OnResult did not receive the same event pointer returned by RunURL")
	}
}

func TestRunRequestPreservesMethodHeadersAndBody(t *testing.T) {
	seen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen <- r.Method + "|" + r.Header.Get("X-SDK-Test") + "|" + string(body)
		w.Header().Set("Server", "RequestEcho/3.1")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	raw := "POST /submit HTTP/1.1\r\nHost: example.com\r\nX-SDK-Test: yes\r\nContent-Length: 7\r\n\r\npayload"
	rr, err := ParseRawRequest(raw, server.URL+"/submit")
	if err != nil {
		t.Fatalf("ParseRawRequest() error = %v", err)
	}

	cfg := NewConfig(WithPassiveModules(software_version_header.New()), WithConcurrency(1), WithMaxPerHost(1))
	results, err := cfg.RunRequest(context.Background(), rr)
	if err != nil {
		t.Fatalf("RunRequest() error = %v", err)
	}
	if len(results) == 0 {
		t.Fatal("RunRequest() returned no findings")
	}

	select {
	case got := <-seen:
		if got != "POST|yes|payload" {
			t.Fatalf("server saw %q, want POST|yes|payload", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive request")
	}
}

func TestRunURLContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := NewConfig(WithPassiveModules(software_version_header.New()), WithConcurrency(1))
	results, err := cfg.RunURL(ctx, "http://127.0.0.1/")
	if err == nil {
		t.Fatal("RunURL() error = nil, want cancellation error")
	}
	if len(results) != 0 {
		t.Fatalf("RunURL() returned %d result(s), want 0", len(results))
	}
}

func TestParseCurl(t *testing.T) {
	rr, err := ParseCurl(`curl -X POST -H 'X-SDK-Test: yes' --data 'payload' http://example.com/submit`)
	if err != nil {
		t.Fatalf("ParseCurl() error = %v", err)
	}
	if rr == nil {
		t.Fatal("ParseCurl() returned nil request")
	}
}
