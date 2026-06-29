package secret_detect

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// SecretFindingSeverity computes the severity and confidence for a Kingfisher
// secret finding based on where and how it was observed.
//
// A secret that Kingfisher validated as live stays Critical/Certain no matter
// where it appears — a confirmed live credential is serious anywhere. For
// unvalidated matches the baseline is High/Firm, with several downgrades:
//
//   - A reCAPTCHA site key (recaptchaSiteKey — see IsReCaptchaSiteKey) or a
//     Google OAuth client ID (oauthClientID — see IsGoogleOAuthClientID) drops to
//     Info/Tentative. Both are public by design — a reCAPTCHA site key is embedded
//     in page HTML/JS so the widget can render, and an OAuth client ID rides in
//     every Google sign-in button — so they outrank every other branch, including
//     a (spurious) validation: a public identifier is never a leaked secret. The
//     paired client *secret* is a separate match and keeps full severity.
//
//   - Matches that ride on a redirect (3xx) response, appear verbatim inside a
//     response header value, or are reflected straight back out of the request
//     (its URL or raw bytes — see SnippetReflectedFromRequest) drop to
//     Low/Tentative. Those are almost always low-value reflections — e.g. an
//     OAuth client_id / state / nonce embedded in a Location URL that merely
//     bounces the browser to an SSO login page, or a Cloudflare Access
//     application id in a /cdn-cgi/access/verify-code/<app-id> SSO URL echoed
//     into the login page — rather than a genuinely leaked secret served in
//     page content.
//
//   - A Google API key (googleAPIKey — see IsGoogleAPIKey) drops to Medium/Firm.
//     The AIza… key family is routinely embedded in client-side code by design,
//     so leakage is billing/quota abuse against the enabled Google APIs rather
//     than account takeover. A live-validated Google key still escalates ahead of
//     this to Critical.
//
//   - A JWT we cannot decode into a usable credential (lowValueJWT — see
//     LowValueJWT) drops to Medium/Tentative. This catches Cloudflare Access and
//     similar SSO pre-auth "meta" tokens that are embedded in login-page URLs and
//     reflected into the page body: they decode to an unauthenticated metadata
//     token (auth_status=NONE, no identity), not a leaked secret.
func SecretFindingSeverity(validated, redirect, inHeader, reflectedFromRequest, lowValueJWT, recaptchaSiteKey, googleAPIKey, oauthClientID bool) (severity.Severity, severity.Confidence) {
	switch {
	case recaptchaSiteKey, oauthClientID:
		return severity.Info, severity.Tentative
	case validated:
		return severity.Critical, severity.Certain
	case redirect || inHeader || reflectedFromRequest:
		return severity.Low, severity.Tentative
	case googleAPIKey:
		return severity.Medium, severity.Firm
	case lowValueJWT:
		return severity.Medium, severity.Tentative
	default:
		return severity.High, severity.Firm
	}
}

// IsRedirectStatus reports whether code is an HTTP 3xx redirect status.
func IsRedirectStatus(code int) bool {
	return code >= 300 && code < 400
}

// JoinHeaderValues concatenates response header values into a single
// newline-delimited blob suitable for snippet containment checks. Header names
// are omitted — only the values can carry a reflected secret (e.g. a Location
// redirect URL).
func JoinHeaderValues(headers []httpmsg.HttpHeader) string {
	if len(headers) == 0 {
		return ""
	}
	var b strings.Builder
	for _, h := range headers {
		b.WriteString(h.Value)
		b.WriteByte('\n')
	}
	return b.String()
}

// SnippetInHeaderValues reports whether the matched secret snippet appears
// verbatim within the response header values blob (see JoinHeaderValues), most
// commonly a Location redirect URL. Kingfisher only scans response bodies, but
// a server's default redirect body echoes the Location URL, so a header-borne
// value surfaces in the body too; matching it back to a header marks it as a
// low-value reflection rather than leaked page content. A blank snippet never
// matches.
func SnippetInHeaderValues(snippet, headerValues string) bool {
	snippet = strings.TrimSpace(snippet)
	if snippet == "" || headerValues == "" {
		return false
	}
	return strings.Contains(headerValues, snippet)
}

// SnippetReflectedFromRequest reports whether the matched secret snippet appears
// verbatim in the request that produced the response — its URL (path or query)
// or anywhere in the raw request bytes.
//
// A value the client itself sent and the server merely echoed into the page is
// a reflection of client-supplied input, not a server-held secret newly leaked
// to the reader. The dominant case is single-sign-on login flows: a Cloudflare
// Access application id sits in the /cdn-cgi/access/verify-code/<app-id> URL and
// is reflected into the login page body, where a generic Cloudflare-token rule
// matches it. The value came from the request, so the client already had it;
// the body reflection is not a new leak, and the match is downgraded rather than
// reported as a High-severity secret. A blank snippet never matches.
func SnippetReflectedFromRequest(snippet, requestURL, rawRequest string) bool {
	snippet = strings.TrimSpace(snippet)
	if snippet == "" {
		return false
	}
	if requestURL != "" && strings.Contains(requestURL, snippet) {
		return true
	}
	return rawRequest != "" && strings.Contains(rawRequest, snippet)
}
