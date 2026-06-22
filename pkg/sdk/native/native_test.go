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
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func withoutOAST() Option {
	enabled := false
	return WithOASTConfig(OASTConfig{Enabled: &enabled})
}

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
		withoutOAST(),
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
		withoutOAST(),
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

	cfg := NewConfig(WithPassiveModules(software_version_header.New()), WithConcurrency(1), WithMaxPerHost(1), withoutOAST())
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

	cfg := NewConfig(WithPassiveModules(software_version_header.New()), WithConcurrency(1), withoutOAST())
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

func TestResultCollectorDeduplicatesByResultEventID(t *testing.T) {
	collector := newResultCollector(nil)
	collector.Emit([]*output.ResultEvent{
		testResult("ssrf-blind", severity.High, "http://example.test/a"),
		testResult("ssrf-blind", severity.High, "http://example.test/a"),
	})

	results := collector.Results()
	if len(results) != 1 {
		t.Fatalf("collector returned %d result(s), want 1", len(results))
	}
}

func TestResultCollectorKeepsDifferentSeverities(t *testing.T) {
	collector := newResultCollector(nil)
	collector.Emit([]*output.ResultEvent{
		testResult("ssrf-blind", severity.High, "http://example.test/a"),
		testResult("ssrf-blind", severity.Info, "http://example.test/a"),
	})

	results := collector.Results()
	if len(results) != 2 {
		t.Fatalf("collector returned %d result(s), want 2", len(results))
	}
}

func TestResultCollectorMergesDuplicateEvidence(t *testing.T) {
	collector := newResultCollector(nil)

	first := testResult("ssrf-blind", severity.High, "http://example.test/a")
	first.ExtractedResults = []string{"callback-a"}
	first.AdditionalEvidence = []string{"evidence-a"}
	first.Request = "GET /first HTTP/1.1"
	first.Response = "HTTP/1.1 200 OK"

	second := testResult("ssrf-blind", severity.High, "http://example.test/a")
	second.ExtractedResults = []string{"callback-a", "callback-b"}
	second.AdditionalEvidence = []string{"evidence-a", "evidence-b"}
	second.Request = "GET /second HTTP/1.1"
	second.Response = "HTTP/1.1 403 Forbidden"

	collector.Emit([]*output.ResultEvent{first, second})

	results := collector.Results()
	if len(results) != 1 {
		t.Fatalf("collector returned %d result(s), want 1", len(results))
	}
	got := results[0]
	if len(got.ExtractedResults) != 1 || got.ExtractedResults[0] != "callback-a" {
		t.Fatalf("ExtractedResults = %#v, want survivor value only", got.ExtractedResults)
	}
	if len(got.AdditionalEvidence) != 3 {
		t.Fatalf("AdditionalEvidence = %#v, want existing evidence, duplicate request/response, and duplicate evidence", got.AdditionalEvidence)
	}
	if got.Request != first.Request {
		t.Fatalf("Request = %q, want first non-empty request", got.Request)
	}
	if got.Response != first.Response {
		t.Fatalf("Response = %q, want first non-empty response", got.Response)
	}
}

func TestResultCollectorOnResultOnlyReceivesUniqueFindings(t *testing.T) {
	var callbacks int
	collector := newResultCollector(func(*Result) {
		callbacks++
	})
	collector.Emit([]*output.ResultEvent{
		testResult("ssrf-blind", severity.High, "http://example.test/a"),
		testResult("ssrf-blind", severity.High, "http://example.test/a"),
		testResult("ssrf-blind", severity.Info, "http://example.test/a"),
	})

	if callbacks != 2 {
		t.Fatalf("OnResult called %d time(s), want 2", callbacks)
	}
}

func testResult(moduleID string, sev severity.Severity, matched string) *output.ResultEvent {
	return &output.ResultEvent{
		ModuleID: moduleID,
		Info: output.Info{
			Description: "blind SSRF callback",
			Severity:    sev,
		},
		Matched: matched,
	}
}
