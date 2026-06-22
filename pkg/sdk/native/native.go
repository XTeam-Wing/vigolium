// Package native exposes a small Go API for running Vigolium's native scanner
// from another Go process.
package native

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/dedup"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

// Result is Vigolium's standard nuclei-compatible JSON result event.
type Result = output.ResultEvent

// ActiveModule is the minimal active-module contract used by the SDK runner.
// Built-in active modules satisfy this without importing the global module
// registry package.
type ActiveModule interface {
	ID() string
	CanProcess(*httpmsg.HttpRequestResponse) bool
	ScanScopes() modkit.ScanScope
	AllowedInsertionPointTypes() modkit.InsertionPointTypeSet
	ScanPerInsertionPoint(*httpmsg.HttpRequestResponse, httpmsg.InsertionPoint, *vighttp.Requester, *modkit.ScanContext) ([]*output.ResultEvent, error)
	ScanPerRequest(*httpmsg.HttpRequestResponse, *vighttp.Requester, *modkit.ScanContext) ([]*output.ResultEvent, error)
	ScanPerHost(*httpmsg.HttpRequestResponse, *vighttp.Requester, *modkit.ScanContext) ([]*output.ResultEvent, error)
}

// PassiveModule is the minimal passive-module contract used by the SDK runner.
type PassiveModule interface {
	ID() string
	CanProcess(*httpmsg.HttpRequestResponse) bool
	ScanScopes() modkit.ScanScope
	ScanPerRequest(*httpmsg.HttpRequestResponse, *modkit.ScanContext) ([]*output.ResultEvent, error)
	ScanPerHost(*httpmsg.HttpRequestResponse, *modkit.ScanContext) ([]*output.ResultEvent, error)
}

// Config controls a native scan run.
type Config struct {
	Concurrency             int
	MaxPerHost              int
	Timeout                 time.Duration
	Retries                 int
	MaxHostError            int
	MaxFindingsPerModule    int
	ProxyURL                string
	Headers                 []string
	Modules                 []string
	ModuleTags              []string
	ActiveModules           []ActiveModule
	PassiveModules          []PassiveModule
	Passive                 bool
	NoTechFilter            bool
	FollowRedirects         bool
	FollowHostRedirects     bool
	DisableRedirects        bool
	IncludeResponseInOutput bool
	OmitResponse            bool

	OnResult func(*Result)
}

// Option mutates Config.
type Option func(*Config)

// NewConfig returns a Config with SDK-friendly defaults.
func NewConfig(opts ...Option) *Config {
	base := types.DefaultOptions()
	cfg := &Config{
		Concurrency:          base.Concurrency,
		MaxPerHost:           base.MaxPerHost,
		Timeout:              base.Timeout,
		Retries:              base.Retries,
		MaxHostError:         base.MaxHostError,
		MaxFindingsPerModule: base.MaxFindingsPerModule,
		Passive:              true,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

func WithConcurrency(v int) Option {
	return func(c *Config) { c.Concurrency = v }
}

func WithMaxPerHost(v int) Option {
	return func(c *Config) { c.MaxPerHost = v }
}

func WithTimeout(v time.Duration) Option {
	return func(c *Config) { c.Timeout = v }
}

func WithRetries(v int) Option {
	return func(c *Config) { c.Retries = v }
}

func WithMaxHostError(v int) Option {
	return func(c *Config) { c.MaxHostError = v }
}

func WithMaxFindingsPerModule(v int) Option {
	return func(c *Config) { c.MaxFindingsPerModule = v }
}

func WithProxy(url string) Option {
	return func(c *Config) { c.ProxyURL = url }
}

func WithHeaders(headers ...string) Option {
	return func(c *Config) { c.Headers = append([]string(nil), headers...) }
}

func WithModules(moduleIDs ...string) Option {
	return func(c *Config) { c.Modules = append([]string(nil), moduleIDs...) }
}

// WithActiveModules sets the active modules to execute. Passing module
// instances keeps the SDK run path independent from CLI global flag resolution.
func WithActiveModules(active ...ActiveModule) Option {
	return func(c *Config) { c.ActiveModules = append([]ActiveModule(nil), active...) }
}

// WithPassiveModules sets the passive modules to execute.
func WithPassiveModules(passive ...PassiveModule) Option {
	return func(c *Config) { c.PassiveModules = append([]PassiveModule(nil), passive...) }
}

func WithModuleTags(tags ...string) Option {
	return func(c *Config) { c.ModuleTags = append([]string(nil), tags...) }
}

func WithPassive(enabled bool) Option {
	return func(c *Config) { c.Passive = enabled }
}

func WithNoTechFilter(enabled bool) Option {
	return func(c *Config) { c.NoTechFilter = enabled }
}

func WithFollowRedirects(enabled bool) Option {
	return func(c *Config) { c.FollowRedirects = enabled }
}

func WithFollowHostRedirects(enabled bool) Option {
	return func(c *Config) { c.FollowHostRedirects = enabled }
}

func WithDisableRedirects(enabled bool) Option {
	return func(c *Config) { c.DisableRedirects = enabled }
}

func WithIncludeResponseInOutput(enabled bool) Option {
	return func(c *Config) { c.IncludeResponseInOutput = enabled }
}

func WithOmitResponse(enabled bool) Option {
	return func(c *Config) { c.OmitResponse = enabled }
}

func WithOnResult(fn func(*Result)) Option {
	return func(c *Config) { c.OnResult = fn }
}

// RunURL scans a single URL and returns all findings.
func (c *Config) RunURL(ctx context.Context, target string) ([]*Result, error) {
	if target == "" {
		return nil, errors.New("no target provided")
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	rr, err := httpmsg.GetRawRequestFromURL(target)
	if err != nil {
		return nil, fmt.Errorf("parse target URL: %w", err)
	}
	return c.runRequests(ctx, []*httpmsg.HttpRequestResponse{rr})
}

// RunRequest scans a single request and returns all findings.
func (c *Config) RunRequest(ctx context.Context, rr *httpmsg.HttpRequestResponse) ([]*Result, error) {
	if rr == nil {
		return nil, errors.New("request is nil")
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	return c.runRequests(ctx, []*httpmsg.HttpRequestResponse{rr})
}

// RunRequests scans a slice of requests and returns all findings.
func (c *Config) RunRequests(ctx context.Context, items []*httpmsg.HttpRequestResponse) ([]*Result, error) {
	if len(items) == 0 {
		return nil, errors.New("no requests provided")
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	return c.runRequests(ctx, items)
}

// ParseRawRequest parses a raw HTTP request with an explicit target URL.
func ParseRawRequest(raw, targetURL string) (*httpmsg.HttpRequestResponse, error) {
	return httpmsg.ParseRawRequestWithURL(raw, targetURL)
}

// ParseCurl parses a single curl command into an HttpRequestResponse.
func ParseCurl(command string) (*httpmsg.HttpRequestResponse, error) {
	return curl.ParseSingleCommand(command)
}

func (c *Config) runRequests(ctx context.Context, items []*httpmsg.HttpRequestResponse) ([]*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	opts := c.options()
	if err := network.Init(opts); err != nil {
		return nil, fmt.Errorf("initialize network: %w", err)
	}
	defer network.Close()

	dedupMgr := dedup.NewManager()
	defer dedupMgr.Close()

	hostLimiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{
		MaxPerHost:    opts.MaxPerHost,
		MaxEntries:    1000,
		EvictAfter:    30 * time.Second,
		EvictInterval: 10 * time.Second,
	})
	defer hostLimiter.Close()

	svc := &services.Services{
		Options:      opts,
		HostLimiter:  hostLimiter,
		DedupManager: dedupMgr,
	}
	if opts.ShouldUseHostError() {
		hostErrors := hosterrors.New(opts.MaxHostError, hosterrors.DefaultMaxHostsCount, nil)
		hostErrors.SetVerbose(opts.Verbose)
		svc.HostErrors = hostErrors
	}

	requester, err := vighttp.NewRequester(opts, svc)
	if err != nil {
		return nil, fmt.Errorf("create HTTP requester: %w", err)
	}

	active, passive := c.modules()
	scanCtx := &modkit.ScanContext{DedupManager: dedupMgr}
	var mu sync.Mutex
	results := make([]*Result, 0)
	emit := func(batch []*output.ResultEvent) {
		for _, result := range batch {
			if result == nil {
				continue
			}
			if result.Type == "" {
				result.Type = "http"
			}
			result.MatcherStatus = true
			if result.Timestamp.IsZero() {
				result.Timestamp = time.Now()
			}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
			if c.OnResult != nil {
				c.OnResult(result)
			}
		}
	}

	for _, item := range items {
		if err := ctxErr(ctx); err != nil {
			return results, err
		}
		if item == nil || item.Request() == nil {
			continue
		}
		scanItem, err := c.ensureResponse(ctx, requester, item)
		if err != nil {
			return results, err
		}
		for _, module := range passive {
			if module == nil || !module.CanProcess(scanItem) {
				continue
			}
			if module.ScanScopes().Has(modkit.ScanScopeRequest) {
				batch, err := module.ScanPerRequest(scanItem, scanCtx)
				if err != nil {
					return results, fmt.Errorf("%s passive request scan: %w", module.ID(), err)
				}
				emit(batch)
			}
			if module.ScanScopes().Has(modkit.ScanScopeHost) {
				batch, err := module.ScanPerHost(scanItem, scanCtx)
				if err != nil {
					return results, fmt.Errorf("%s passive host scan: %w", module.ID(), err)
				}
				emit(batch)
			}
		}
		points, err := scanItem.CreateInsertionPoints(true)
		if err != nil {
			return results, fmt.Errorf("create insertion points: %w", err)
		}
		for _, module := range active {
			if module == nil || !module.CanProcess(scanItem) {
				continue
			}
			if module.ScanScopes().Has(modkit.ScanScopeRequest) {
				batch, err := module.ScanPerRequest(scanItem, requester, scanCtx)
				if err != nil {
					return results, fmt.Errorf("%s active request scan: %w", module.ID(), err)
				}
				emit(batch)
			}
			if module.ScanScopes().Has(modkit.ScanScopeHost) {
				batch, err := module.ScanPerHost(scanItem, requester, scanCtx)
				if err != nil {
					return results, fmt.Errorf("%s active host scan: %w", module.ID(), err)
				}
				emit(batch)
			}
			if !module.ScanScopes().Has(modkit.ScanScopeInsertionPoint) {
				continue
			}
			allowed := module.AllowedInsertionPointTypes()
			for _, point := range points {
				if !allowed.Contains(point.Type()) {
					continue
				}
				batch, err := module.ScanPerInsertionPoint(scanItem, point, requester, scanCtx)
				if err != nil {
					return results, fmt.Errorf("%s insertion-point scan: %w", module.ID(), err)
				}
				emit(batch)
				if opts.MaxFindingsPerModule > 0 && countModuleResults(results, module.ID()) >= opts.MaxFindingsPerModule {
					break
				}
			}
		}
	}
	return results, nil
}

func (c *Config) ensureResponse(ctx context.Context, requester *vighttp.Requester, item *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error) {
	if item.HasResponse() {
		return item, nil
	}
	resp, _, err := requester.ExecuteContext(ctx, item, vighttp.Options{})
	if err != nil {
		return nil, fmt.Errorf("fetch baseline response: %w", err)
	}
	defer resp.Close()
	return item.WithResponse(httpmsg.NewHttpResponse(resp.FullResponseBytes())), nil
}

func (c *Config) options() *types.Options {
	base := types.DefaultOptions()
	base.Concurrency = positiveOrDefault(c.Concurrency, base.Concurrency)
	base.MaxPerHost = positiveOrDefault(c.MaxPerHost, base.MaxPerHost)
	base.Timeout = durationOrDefault(c.Timeout, base.Timeout)
	base.Retries = c.Retries
	base.MaxHostError = c.MaxHostError
	base.MaxFindingsPerModule = c.MaxFindingsPerModule
	base.ProxyURL = c.ProxyURL
	base.Headers = append([]string(nil), c.Headers...)
	base.Modules = c.resolvedModules()
	if c.Passive {
		base.PassiveModules = []string{"all"}
	} else {
		base.PassiveModules = nil
	}
	base.NoTechFilter = c.NoTechFilter
	base.FollowRedirects = c.FollowRedirects
	base.FollowHostRedirects = c.FollowHostRedirects
	base.DisableRedirects = c.DisableRedirects
	base.IncludeResponseInOutput = c.IncludeResponseInOutput
	base.OmitResponse = c.OmitResponse
	base.Silent = true
	base.ScanUUID = "sdk-" + uuid.NewString()
	base.ProjectUUID = "default"
	return base
}

func (c *Config) modules() ([]ActiveModule, []PassiveModule) {
	active := append([]ActiveModule(nil), c.ActiveModules...)
	if !c.Passive {
		return active, nil
	}
	return active, append([]PassiveModule(nil), c.PassiveModules...)
}

func (c *Config) resolvedModules() []string {
	var patterns []string
	patterns = append(patterns, c.Modules...)
	if len(patterns) == 0 {
		return nil
	}
	return patterns
}

func countModuleResults(results []*Result, moduleID string) int {
	count := 0
	for _, result := range results {
		if result != nil && result.ModuleID == moduleID {
			count++
		}
	}
	return count
}

func positiveOrDefault(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

func durationOrDefault(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
