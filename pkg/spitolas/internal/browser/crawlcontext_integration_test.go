//go:build integration && (linux || darwin)

package browser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// These tests launch a REAL headless browser, so they are gated behind the
// `integration` tag. Run with:
//   go test -tags=integration -run TestCrawlContext ./pkg/spitolas/internal/browser/...
//
// They are the regression guard for the spidering timeout overrun: the crawl's
// deadline must propagate into rod's per-operation timeouts via the page's bound
// context (Browser.SetCrawlContext → NewPage → rodPage.Context). Before the fix,
// a navigation to a hung endpoint blocked for the full PageLoadTimeout (30s)
// regardless of how little time was left in the crawl budget, so the spider
// routinely ran far past its max-duration.

// hangingServer returns a server whose handler blocks until the client (the
// browser) cancels the request — i.e. it never responds on its own. The browser
// only gives up when its navigation timeout (the bound crawl context here)
// fires.
func hangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newHeadlessBrowser(t *testing.T, targetURL string) *Browser {
	t.Helper()
	cfg, err := config.New(targetURL)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	cfg.Headless = true
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("New browser: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// TestCrawlContextAbortsHungNavigation is the core regression test: a page
// created after SetCrawlContext must abort a hung navigation when the bound
// context's deadline fires (~deadline), NOT after the much longer
// PageLoadTimeout. A pass here can only happen if the deadline reached rod.
func TestCrawlContextAbortsHungNavigation(t *testing.T) {
	srv := hangingServer(t)
	b := newHeadlessBrowser(t, srv.URL)

	const deadline = 3 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	b.SetCrawlContext(ctx)

	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}

	start := time.Now()
	err = page.Navigate(srv.URL)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Navigate to a hung endpoint returned nil error, want a deadline/cancel error")
	}
	// The bound deadline is 3s; PageLoadTimeout defaults to 30s. Anything well
	// under 30s proves the crawl deadline aborted the op rather than rod's fixed
	// per-op timeout. Generous upper bound to stay non-flaky on slow CI.
	if elapsed > 15*time.Second {
		t.Fatalf("Navigate took %s — deadline did not propagate into the browser op "+
			"(PageLoadTimeout=%s; want it to abort near the %s crawl deadline)",
			elapsed, b.config.PageLoadTimeout, deadline)
	}
	t.Logf("hung navigation aborted in %s (deadline %s, PageLoadTimeout %s)",
		elapsed, deadline, b.config.PageLoadTimeout)
}

// TestUnboundPageIgnoresShortContext is a control proving the binding is what
// does the work: a page created WITHOUT SetCrawlContext does not see the short
// context and blocks until PageLoadTimeout. We shorten PageLoadTimeout so the
// control stays fast while still being clearly longer than the (ignored) ctx.
func TestUnboundPageIgnoresShortContext(t *testing.T) {
	srv := hangingServer(t)
	b := newHeadlessBrowser(t, srv.URL)
	b.config.PageLoadTimeout = 5 * time.Second // keep the control test fast

	// A short context that, if it leaked into the page, would abort in ~500ms.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	// NOTE: deliberately NOT calling SetCrawlContext — the page must not inherit ctx.
	_ = ctx

	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}

	start := time.Now()
	_ = page.Navigate(srv.URL)
	elapsed := time.Since(start)

	// Without binding, the only stop signal is PageLoadTimeout (5s here), so the
	// nav must take meaningfully longer than the 500ms context it never saw.
	if elapsed < 3*time.Second {
		t.Fatalf("unbound page aborted in %s — it should ignore the external context "+
			"and run until PageLoadTimeout (%s)", elapsed, b.config.PageLoadTimeout)
	}
	t.Logf("unbound navigation ran %s (PageLoadTimeout %s), correctly ignoring the external ctx",
		elapsed, b.config.PageLoadTimeout)
}

// TestPageCloseAfterCrawlContextCancel guards the shutdown path: Page.Close must
// detach from the (now cancelled) crawl context and still close the tab cleanly,
// so a deadline that fires mid-crawl doesn't leak tabs during teardown.
func TestPageCloseAfterCrawlContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	b := newHeadlessBrowser(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	b.SetCrawlContext(ctx)

	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	if err := page.Navigate(srv.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}

	// Simulate the crawl deadline firing, then tear the page down.
	cancel()

	done := make(chan error, 1)
	go func() { done <- page.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close after crawl-context cancel returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Page.Close hung after the crawl context was cancelled — it must detach to a live context")
	}
}

// TestCrawlContextAbortsEval guards the eval forever-hang: page.Eval/EvalAwait/
// EvalWithArgs previously issued the Runtime.evaluate CDP call on the browser's
// deadline-less background context, so an eval against a wedged/unresponsive
// renderer (busy JS main thread, anti-bot challenge, captcha page) blocked
// forever — the real cause of the spider hanging past max-duration on a /login
// page. They now run on the bound, per-call-capped page context, so a fired
// crawl deadline aborts them promptly instead of hanging.
func TestCrawlContextAbortsEval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	b := newHeadlessBrowser(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	b.SetCrawlContext(ctx)

	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	if err := page.Navigate(srv.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}

	// Simulate the crawl deadline firing mid-crawl, then run evals. Every eval
	// path must observe the cancelled context and return rather than block.
	cancel()

	done := make(chan struct{})
	go func() {
		_, _ = page.Eval("1+1")
		_, _ = page.EvalWithArgs("() => 1")
		_, _ = page.EvalAwait("Promise.resolve(1)", 5*time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("eval hung after the crawl context was cancelled — the deadline did not reach the Runtime.evaluate CDP call")
	}
}

// TestCrawlContextAbortsElementOps guards the same class of hang one layer down:
// element ops (Text/HTML/Attribute/Eval/Visible/…) issue CDP DOM/Runtime calls on
// the element, which inherits the page's bound context. They must observe a fired
// crawl deadline and return rather than block on a wedged renderer.
func TestCrawlContextAbortsElementOps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body><div id=x>hi</div></body></html>"))
	}))
	defer srv.Close()

	b := newHeadlessBrowser(t, srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	b.SetCrawlContext(ctx)

	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("NewPage: %v", err)
	}
	if err := page.Navigate(srv.URL); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	el, err := page.Element("#x")
	if err != nil {
		t.Fatalf("Element: %v", err)
	}

	// Crawl deadline fires; every element op must return rather than hang.
	cancel()

	done := make(chan struct{})
	go func() {
		_, _ = el.Text()
		_, _ = el.HTML()
		_, _ = el.Attribute("id")
		_ = el.IsVisible()
		_, _ = el.EvalWithResult("() => 1")
		_ = el.Focus()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("element ops hung after the crawl context was cancelled — the deadline did not reach the element CDP calls")
	}
}
