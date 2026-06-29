package database

import (
	"context"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// TestRepositorySaveCallbacks verifies the OnRecordSaved / OnFindingSaved hooks
// (used by the server's --mirror-fs mirror) fire exactly once per genuinely new
// row and never on a dedup hit / dedup-append.
func TestRepositorySaveCallbacks(t *testing.T) {
	db := newTestDB(t)
	repo := NewRepository(db)
	ctx := context.Background()

	var mu sync.Mutex
	var recHits, findHits int
	repo.OnRecordSaved = func(*HTTPRecord) { mu.Lock(); recHits++; mu.Unlock() }
	repo.OnFindingSaved = func(*Finding) { mu.Lock(); findHits++; mu.Unlock() }

	saveRecord := func() {
		rr, err := httpmsg.ParseRawRequest("GET /x HTTP/1.1\r\nHost: cb.example\r\n\r\n")
		if err != nil {
			t.Fatalf("ParseRawRequest: %v", err)
		}
		rr = rr.WithResponse(httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok")))
		if _, err := repo.SaveRecord(ctx, rr, "test", DefaultProjectUUID); err != nil {
			t.Fatalf("SaveRecord: %v", err)
		}
	}

	// First save inserts → one hit. Identical request dedups → no second hit.
	saveRecord()
	saveRecord()
	mu.Lock()
	if recHits != 1 {
		t.Errorf("OnRecordSaved fired %d times, want 1 (dedup must not fire)", recHits)
	}
	mu.Unlock()

	saveFinding := func() {
		f := &Finding{
			HTTPRecordUUIDs: []string{},
			FindingHash:     "hash-1",
			ModuleID:        "mod",
			ModuleName:      "Module",
			Severity:        "high",
			Confidence:      "firm",
			Hostname:        "cb.example",
		}
		if err := repo.SaveFindingDirect(ctx, f); err != nil {
			t.Fatalf("SaveFindingDirect: %v", err)
		}
	}

	// First insert fires; same finding_hash dedup-appends → no second hit.
	saveFinding()
	saveFinding()
	mu.Lock()
	if findHits != 1 {
		t.Errorf("OnFindingSaved fired %d times, want 1 (dedup-append must not fire)", findHits)
	}
	mu.Unlock()
}
