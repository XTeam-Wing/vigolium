package native

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/ssrf_detection"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

func TestSDKSSRFDetectionAgainstCTFTarget(t *testing.T) {
	const target = "https://7f6f3afa213bb9731cad4468.http-ctf2.dasctf.com/vul/ssrf/ssrf_fgc.php?file=http://127.0.0.1/vul/vul/ssrf/ssrf_info/info2.php"

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	module := &countingSSRFModule{Module: ssrf_detection.New()}
	cfg := NewConfig(
		WithActiveModules(module),
		WithPassive(false),
		WithConcurrency(4),
		WithMaxPerHost(2),
		WithTimeout(15*time.Second),
		WithMaxFindingsPerModule(5),
	)

	results, err := cfg.RunURL(ctx, target)
	if err != nil {
		t.Fatalf("RunURL() error = %v", err)
	}
	if module.calls.Load() == 0 {
		t.Fatal("expected ssrf-detection module to scan at least one insertion point")
	}
	t.Logf("ssrf-detection scanned %d insertion point(s), findings=%d", module.calls.Load(), len(results))
}

type countingSSRFModule struct {
	*ssrf_detection.Module
	calls atomic.Int64
}

func (m *countingSSRFModule) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *vighttp.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	m.calls.Add(1)
	return m.Module.ScanPerInsertionPoint(ctx, ip, httpClient, scanCtx)
}
