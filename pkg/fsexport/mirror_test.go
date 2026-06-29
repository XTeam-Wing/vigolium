package fsexport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
)

func sampleRecord(uuid string) *database.HTTPRecord {
	return &database.HTTPRecord{
		UUID:                uuid,
		Scheme:              "https",
		Hostname:            "api.example",
		Port:                443,
		Method:              "GET",
		Path:                "/users",
		HasResponse:         true,
		StatusCode:          200,
		ResponseContentType: "application/json; charset=utf-8",
		RawRequest:          []byte("GET /users HTTP/1.1\r\nHost: api.example\r\n\r\n"),
		RawResponse:         []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}"),
	}
}

// TestMirrorWritesTreeAndIndexes drives the live mirror through one record + one
// linked finding and asserts the on-disk tree, the @target line, the decoded
// body, the append-only index.jsonl files, and the finding→traffic cross-link.
func TestMirrorWritesTreeAndIndexes(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMirror(dir, false)
	require.NoError(t, err)

	m.OnRecord(sampleRecord("rec-1"))
	m.OnFinding(&database.Finding{
		HTTPRecordUUIDs: []string{"rec-1"},
		ModuleID:        "broken-auth",
		ModuleName:      "Broken Authentication",
		ModuleType:      "active",
		Severity:        "high",
		Confidence:      "firm",
		Hostname:        "api.example",
		URL:             "https://api.example/users",
	})
	m.Close() // drains all queued jobs

	// .req leads with @target then the raw request verbatim.
	req, err := os.ReadFile(filepath.Join(dir, "traffic", "api.example", "0001.req"))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(req), "@target https://api.example\nGET /users HTTP/1.1\r\n"),
		"unexpected .req: %q", string(req))

	// .resp.body is written (decoded).
	body, err := os.ReadFile(filepath.Join(dir, "traffic", "api.example", "0001.resp.body"))
	require.NoError(t, err)
	assert.Equal(t, `{"ok":true}`, string(body))

	// traffic index.jsonl: one line, parseable, finding stays null in live mode.
	traffic := readJSONLines(t, filepath.Join(dir, "traffic", "index.jsonl"))
	require.Len(t, traffic, 1)
	assert.Equal(t, "0001", traffic[0]["id"])
	assert.Equal(t, "GET", traffic[0]["method"])
	assert.Equal(t, "/users", traffic[0]["url"])
	assert.EqualValues(t, 200, traffic[0]["status"])
	assert.Equal(t, "application/json", traffic[0]["content_type"])
	assert.Nil(t, traffic[0]["finding"])

	// finding markdown cross-links to the exact .req file AND embeds the linked
	// record's request/response inline so it's self-contained.
	md, err := os.ReadFile(filepath.Join(dir, "findings", "api.example", "0001.md"))
	require.NoError(t, err)
	mds := string(md)
	assert.Contains(t, mds, "# HIGH — Broken Authentication")
	assert.Contains(t, mds, "../../traffic/api.example/0001.req")
	assert.Contains(t, mds, "## Request")
	assert.Contains(t, mds, "GET /users HTTP/1.1", "raw request must be embedded inline")
	assert.NotContains(t, mds, "@target", "the synthetic @target marker line must be stripped from the inline request")
	assert.Contains(t, mds, "## Response")
	assert.Contains(t, mds, `{"ok":true}`, "decoded response body must be embedded inline")

	// findings index.jsonl links to the traffic path.
	findings := readJSONLines(t, filepath.Join(dir, "findings", "index.jsonl"))
	require.Len(t, findings, 1)
	assert.Equal(t, "api.example/0001.md", findings[0]["path"])
	tr, _ := findings[0]["traffic"].([]any)
	require.Len(t, tr, 1)
	assert.Equal(t, "api.example/0001", tr[0])
}

// TestMirrorResumesSequence verifies a restart continues per-host numbering from
// the existing tree instead of overwriting 0001.
func TestMirrorResumesSequence(t *testing.T) {
	dir := t.TempDir()

	m1, err := NewMirror(dir, false)
	require.NoError(t, err)
	m1.OnRecord(sampleRecord("rec-1"))
	m1.Close()

	// A fresh mirror over the same dir must resume at 0002.
	m2, err := NewMirror(dir, false)
	require.NoError(t, err)
	m2.OnRecord(sampleRecord("rec-2"))
	m2.Close()

	_, err = os.Stat(filepath.Join(dir, "traffic", "api.example", "0001.req"))
	require.NoError(t, err, "first record must be preserved")
	_, err = os.Stat(filepath.Join(dir, "traffic", "api.example", "0002.req"))
	require.NoError(t, err, "second session must resume at 0002, not overwrite 0001")

	// index.jsonl is append-only across sessions → two lines.
	traffic := readJSONLines(t, filepath.Join(dir, "traffic", "index.jsonl"))
	require.Len(t, traffic, 2)
}

// TestMirrorOmitResponse drops the .resp.* files but keeps .req + index.
func TestMirrorOmitResponse(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMirror(dir, true)
	require.NoError(t, err)
	m.OnRecord(sampleRecord("rec-1"))
	m.Close()

	hostDir := filepath.Join(dir, "traffic", "api.example")
	_, err = os.Stat(filepath.Join(hostDir, "0001.req"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(hostDir, "0001.resp.body"))
	assert.True(t, os.IsNotExist(err), ".resp.body must be omitted")
}

// readJSONLines reads a JSONL file into a slice of generic maps.
func readJSONLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &m))
		out = append(out, m)
	}
	return out
}
