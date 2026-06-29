package fsexport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/database"
)

// writeLinkedFiles writes the .req/.resp.headers/.resp.body trio ReadLinkedRecord
// reads back, mirroring what the traffic pass produced on disk.
func writeLinkedFiles(t *testing.T, root, relPath, req, head, body string) {
	t.Helper()
	dir := filepath.Join(root, filepath.Dir(relPath))
	require.NoError(t, os.MkdirAll(dir, 0o755))
	base := filepath.Join(root, filepath.FromSlash(relPath))
	require.NoError(t, os.WriteFile(base+".req", []byte(req), 0o644))
	if head != "" {
		require.NoError(t, os.WriteFile(base+".resp.headers", []byte(head), 0o644))
	}
	if body != "" {
		require.NoError(t, os.WriteFile(base+".resp.body", []byte(body), 0o644))
	}
}

// TestReadLinkedRecord checks the @target strip, the response head/body load, and
// the inline body cap with its truncation flag.
func TestReadLinkedRecord(t *testing.T) {
	root := t.TempDir()
	bigBody := strings.Repeat("A", InlineBodyCap+512)
	writeLinkedFiles(t, root, "h.example/0001",
		"@target https://h.example\nGET /x HTTP/1.1\r\nHost: h.example\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
		bigBody)

	lr := ReadLinkedRecord(root, "h.example/0001", false)
	assert.Equal(t, "h.example/0001", lr.Path)
	assert.Equal(t, "GET /x HTTP/1.1\r\nHost: h.example\r\n\r\n", lr.Request, "@target marker must be stripped")
	assert.True(t, strings.HasPrefix(lr.ResponseHead, "HTTP/1.1 200 OK"))
	assert.Len(t, lr.ResponseBody, InlineBodyCap, "body must be capped to InlineBodyCap")
	assert.True(t, lr.BodyTruncated)

	// omitResponse loads only the request.
	lr2 := ReadLinkedRecord(root, "h.example/0001", true)
	assert.NotEmpty(t, lr2.Request)
	assert.Empty(t, lr2.ResponseHead)
	assert.Empty(t, lr2.ResponseBody)
}

// TestRenderFindingPrefersOwnEvidence verifies an active finding's own captured
// request/response win over the linked record for the inline section, while the
// linked record still drives the Traffic cross-links.
func TestRenderFindingPrefersOwnEvidence(t *testing.T) {
	f := &database.Finding{
		ModuleID:   "xss",
		ModuleName: "Reflected XSS",
		Severity:   "high",
		Confidence: "firm",
		Request:    "GET /q=PAYLOAD HTTP/1.1\r\nHost: t.example",
		Response:   "HTTP/1.1 200 OK\r\n\r\n<script>PAYLOAD</script>",
	}
	linked := []LinkedRecord{{
		Path:         "t.example/0007",
		Request:      "GET /stored HTTP/1.1\r\nHost: t.example",
		ResponseHead: "HTTP/1.1 200 OK\r\n\r\n",
		ResponseBody: "stored-body",
	}}
	md := string(RenderFindingMarkdown(f, linked, "out-traffic"))

	assert.Contains(t, md, "GET /q=PAYLOAD", "inline request must come from the finding's own evidence")
	assert.Contains(t, md, "<script>PAYLOAD</script>", "inline response must come from the finding's own evidence")
	assert.NotContains(t, md, "stored-body", "linked body must not override the finding's own response")
	assert.Contains(t, md, "../../out-traffic/t.example/0007.req", "Traffic links still point at the linked record")
}

// TestRenderFindingTruncationNote checks the capped-body note links out to the
// full .resp.body file.
func TestRenderFindingTruncationNote(t *testing.T) {
	f := &database.Finding{ModuleID: "idor", ModuleName: "IDOR", Severity: "info", Confidence: "tentative"}
	linked := []LinkedRecord{{
		Path:          "t.example/0020",
		Request:       "GET /19 HTTP/1.1\r\nHost: t.example",
		ResponseHead:  "HTTP/1.1 200 OK\r\n\r\n",
		ResponseBody:  "capped",
		BodyTruncated: true,
	}}
	md := string(RenderFindingMarkdown(f, linked, "out-traffic"))
	assert.Contains(t, md, "## Request")
	assert.Contains(t, md, "## Response")
	assert.Contains(t, md, "truncated to 32 KB")
	assert.Contains(t, md, "../../out-traffic/t.example/0020.resp.body")
}

// TestRenderFindingNoEvidence verifies a finding with neither own nor linked
// traffic renders without a Request/Response/Traffic section and doesn't panic.
func TestRenderFindingNoEvidence(t *testing.T) {
	f := &database.Finding{ModuleID: "m", ModuleName: "M", Severity: "low", Confidence: "firm", Description: "desc"}
	md := string(RenderFindingMarkdown(f, nil, "out-traffic"))
	assert.Contains(t, md, "## Description")
	assert.NotContains(t, md, "## Request")
	assert.NotContains(t, md, "## Response")
	assert.NotContains(t, md, "## Traffic")
}
