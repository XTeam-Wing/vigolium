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
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/dedup"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats/curl"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/oast"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types"
)

// Result is Vigolium's standard nuclei-compatible JSON result event.
type Result = output.ResultEvent

// ActiveModule is the minimal active-module contract used by the SDK runner.
// Built-in active modules satisfy this without importing the global module
// registry package.
type ActiveModule interface {
	modules.Module
	AllowedInsertionPointTypes() modkit.InsertionPointTypeSet
	ScanPerInsertionPoint(*httpmsg.HttpRequestResponse, httpmsg.InsertionPoint, *vighttp.Requester, *modkit.ScanContext) ([]*output.ResultEvent, error)
	ScanPerRequest(*httpmsg.HttpRequestResponse, *vighttp.Requester, *modkit.ScanContext) ([]*output.ResultEvent, error)
	ScanPerHost(*httpmsg.HttpRequestResponse, *vighttp.Requester, *modkit.ScanContext) ([]*output.ResultEvent, error)
}

// PassiveModule is the minimal passive-module contract used by the SDK runner.
type PassiveModule interface {
	modules.Module
	ScanPerRequest(*httpmsg.HttpRequestResponse, *modkit.ScanContext) ([]*output.ResultEvent, error)
	ScanPerHost(*httpmsg.HttpRequestResponse, *modkit.ScanContext) ([]*output.ResultEvent, error)
}

// OASTConfig controls out-of-band callback detection for native SDK scans.
// A nil Enabled value keeps the SDK default enabled behavior.
type OASTConfig struct {
	Enabled         *bool
	ServerURL       string
	Token           string
	PollInterval    int
	GracePeriod     int
	OastURL         string
	BlindXSSSrc     string
	EnabledBlindXSS bool
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
	OAST                    OASTConfig

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

// WithOASTConfig sets OAST callback detection options. OAST is enabled by
// default; pass Enabled=false explicitly to disable it.
func WithOASTConfig(cfg OASTConfig) Option {
	return func(c *Config) { c.OAST = cfg }
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

	collector := newResultCollector(c.OnResult)
	emit := collector.Emit

	oastService, err := oast.New(c.oastConfig(), func(result *output.ResultEvent) {
		emit([]*output.ResultEvent{result})
	}, nil, opts.ScanUUID, opts.ProjectUUID, nil)
	if err != nil {
		return collector.Results(), fmt.Errorf("create OAST service: %w", err)
	}
	origins := newOriginStore()
	if oastService != nil {
		oastService.SetOriginResolver(origins.Get)
		oastService.Start()
		defer oastService.Close()
	}

	active, passive := c.modules()
	scanCtx := &modkit.ScanContext{DedupManager: dedupMgr, OASTProvider: oastService}

	for _, item := range items {
		if err := ctxErr(ctx); err != nil {
			return collector.Results(), err
		}
		if item == nil || item.Request() == nil {
			continue
		}
		scanItem, err := c.ensureResponse(ctx, requester, item)
		if err != nil {
			return collector.Results(), err
		}
		if oastService != nil {
			origins.Add(scanItem)
		}
		for _, module := range passive {
			if module == nil || !module.CanProcess(scanItem) {
				continue
			}
			if module.ScanScopes().Has(modkit.ScanScopeRequest) {
				batch, err := module.ScanPerRequest(scanItem, scanCtx)
				if err != nil {
					return collector.Results(), fmt.Errorf("%s passive request scan: %w", module.ID(), err)
				}
				collector.EmitModuleResults(module, batch)
			}
			if module.ScanScopes().Has(modkit.ScanScopeHost) {
				batch, err := module.ScanPerHost(scanItem, scanCtx)
				if err != nil {
					return collector.Results(), fmt.Errorf("%s passive host scan: %w", module.ID(), err)
				}
				collector.EmitModuleResults(module, batch)
			}
		}
		points, err := scanItem.CreateInsertionPoints(true)
		if err != nil {
			return collector.Results(), fmt.Errorf("create insertion points: %w", err)
		}
		for _, module := range active {
			if module == nil || !module.CanProcess(scanItem) {
				continue
			}
			if module.ScanScopes().Has(modkit.ScanScopeRequest) {
				batch, err := module.ScanPerRequest(scanItem, requester, scanCtx)
				if err != nil {
					return collector.Results(), fmt.Errorf("%s active request scan: %w", module.ID(), err)
				}
				collector.EmitModuleResults(module, batch)
			}
			if module.ScanScopes().Has(modkit.ScanScopeHost) {
				batch, err := module.ScanPerHost(scanItem, requester, scanCtx)
				if err != nil {
					return collector.Results(), fmt.Errorf("%s active host scan: %w", module.ID(), err)
				}
				collector.EmitModuleResults(module, batch)
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
					return collector.Results(), fmt.Errorf("%s insertion-point scan: %w", module.ID(), err)
				}
				collector.EmitModuleResults(module, batch)
				if opts.MaxFindingsPerModule > 0 && collector.CountModuleResults(module.ID()) >= opts.MaxFindingsPerModule {
					break
				}
			}
		}
	}
	if oastService != nil {
		oastService.Flush()
	}
	return collector.Results(), nil
}

type resultCollector struct {
	mu       sync.Mutex
	order    []string
	byID     map[string]*Result
	onResult func(*Result)
}

func newResultCollector(onResult func(*Result)) *resultCollector {
	return &resultCollector{
		order:    make([]string, 0),
		byID:     make(map[string]*Result),
		onResult: onResult,
	}
}

func (c *resultCollector) Emit(batch []*output.ResultEvent) {
	for _, result := range batch {
		if result == nil {
			continue
		}
		normalizeResult(result)
		id := result.ID()

		var first *Result
		c.mu.Lock()
		if existing, ok := c.byID[id]; ok {
			mergeResult(existing, result)
		} else {
			c.byID[id] = result
			c.order = append(c.order, id)
			first = result
		}
		c.mu.Unlock()

		if first != nil && c.onResult != nil {
			c.onResult(first)
		}
	}
}

func (c *resultCollector) EmitModuleResults(module modules.Module, batch []*output.ResultEvent) {
	for _, result := range batch {
		completeModuleResult(result, module)
	}
	c.Emit(batch)
}

func completeModuleResult(result *output.ResultEvent, module modules.Module) {
	if result == nil || module == nil {
		return
	}
	if result.ModuleID == "" {
		result.ModuleID = module.ID()
	}
	if result.Info.Name == "" {
		result.Info.Name = module.Name()
	}
	if result.Info.Description == "" {
		result.Info.Description = module.Description()
	}
	if result.Info.Severity == 0 {
		result.Info.Severity = module.Severity()
	}
	if result.Info.Confidence == 0 {
		result.Info.Confidence = module.Confidence()
	}
	if len(result.Info.Tags) == 0 {
		result.Info.Tags = append([]string(nil), module.Tags()...)
	}
}

func (c *resultCollector) Results() []*Result {
	c.mu.Lock()
	defer c.mu.Unlock()

	results := make([]*Result, 0, len(c.order))
	for _, id := range c.order {
		if result := c.byID[id]; result != nil {
			results = append(results, result)
		}
	}
	return results
}

func (c *resultCollector) CountModuleResults(moduleID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	for _, result := range c.byID {
		if result != nil && result.ModuleID == moduleID {
			count++
		}
	}
	return count
}

func normalizeResult(result *Result) {
	if result.Type == "" {
		result.Type = "http"
	}
	if result.Matched == "" {
		result.Matched = result.URL
	}
	result.MatcherStatus = true
	if result.Timestamp.IsZero() {
		result.Timestamp = time.Now()
	}
}

func mergeResult(existing, incoming *Result) {
	existing.AdditionalEvidence = appendUniqueEvidence(existing.AdditionalEvidence, buildResultEvidence(existing.Request, existing.Response), buildResultEvidence(incoming.Request, incoming.Response))
	existing.AdditionalEvidence = appendUniqueEvidence(existing.AdditionalEvidence, buildResultEvidence(existing.Request, existing.Response), incoming.AdditionalEvidence...)

	if existing.Request == "" {
		existing.Request = incoming.Request
	}
	if existing.Response == "" {
		existing.Response = incoming.Response
	}
	if existing.URL == "" {
		existing.URL = incoming.URL
	}
	if existing.Host == "" {
		existing.Host = incoming.Host
	}
	if existing.Scheme == "" {
		existing.Scheme = incoming.Scheme
	}
	if existing.IP == "" {
		existing.IP = incoming.IP
	}
	if len(existing.Metadata) == 0 && len(incoming.Metadata) > 0 {
		existing.Metadata = incoming.Metadata
	}
	if existing.Timestamp.IsZero() {
		existing.Timestamp = incoming.Timestamp
	}
	existing.MatcherStatus = existing.MatcherStatus || incoming.MatcherStatus
}

func appendUniqueEvidence(existing []string, primary string, incoming ...string) []string {
	if len(incoming) == 0 {
		return existing
	}
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	if primary != "" {
		seen[primary] = struct{}{}
	}
	for _, item := range existing {
		seen[item] = struct{}{}
	}
	for _, item := range incoming {
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		existing = append(existing, item)
	}
	return existing
}

func buildResultEvidence(request, response string) string {
	if request == "" && response == "" {
		return ""
	}
	return request + output.EvidenceSeparator + response
}

type originStore struct {
	mu      sync.RWMutex
	records map[string]*database.HTTPRecord
}

func newOriginStore() *originStore {
	return &originStore{records: make(map[string]*database.HTTPRecord)}
}

func (s *originStore) Add(item *httpmsg.HttpRequestResponse) {
	if s == nil || item == nil || item.Request() == nil {
		return
	}
	hash := item.Request().ID()
	if hash == "" {
		return
	}

	record := &database.HTTPRecord{
		Method:     item.Request().Method(),
		RawRequest: append([]byte(nil), item.Request().Raw()...),
	}
	if target := item.Target(); target != "" {
		record.URL = target
	}
	if item.HasResponse() && item.Response() != nil {
		record.RawResponse = append([]byte(nil), item.Response().Raw()...)
	}

	s.mu.Lock()
	s.records[hash] = record
	s.mu.Unlock()
}

func (s *originStore) Get(requestHash string) *database.HTTPRecord {
	if s == nil || requestHash == "" {
		return nil
	}
	s.mu.RLock()
	record := s.records[requestHash]
	s.mu.RUnlock()
	return record
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

func (c *Config) oastConfig() *config.OASTConfig {
	cfg := config.DefaultOASTConfig()
	if c.OAST.Enabled != nil {
		cfg.Enabled = *c.OAST.Enabled
	}
	if c.OAST.ServerURL != "" {
		cfg.ServerURL = c.OAST.ServerURL
	}
	if c.OAST.Token != "" {
		cfg.Token = c.OAST.Token
	}
	if c.OAST.PollInterval > 0 {
		cfg.PollInterval = c.OAST.PollInterval
	}
	if c.OAST.GracePeriod > 0 {
		cfg.GracePeriod = c.OAST.GracePeriod
	}
	if c.OAST.OastURL != "" {
		cfg.OastURL = c.OAST.OastURL
	}
	if c.OAST.BlindXSSSrc != "" {
		cfg.BlindXSSSrc = c.OAST.BlindXSSSrc
	}
	cfg.EnabledBlindXSS = c.OAST.EnabledBlindXSS
	return cfg
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
