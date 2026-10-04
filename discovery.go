package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const discoveryTTL = time.Hour

// metadata is the part of the OIDC discovery document the plugin uses.
type metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	RevocationEndpoint    string   `json:"revocation_endpoint"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

type cachedMeta struct {
	meta    *metadata
	fetched time.Time
}

// issuerOf is the issuer the provider is configured with.
func (pr *provider) issuerOf() string {
	if pr.cfg.Issuer != "" {
		return pr.cfg.Issuer
	}
	return pr.preset.issuer
}

// issuerMatches reports whether got is the provider's issuer: exactly, or, for
// a template preset with no Issuer configured, with a single non-empty path
// segment for {tenantid}. A configured Issuer (one Microsoft tenant) must match
// exactly.
func issuerMatches(pr *provider, got string) bool {
	if got == pr.issuerOf() {
		return true
	}
	if pr.cfg.Issuer != "" {
		return false
	}
	tpl := pr.preset.issuerTemplate
	prefix, suffix, ok := strings.Cut(tpl, "{tenantid}")
	if !ok || len(got) < len(prefix)+len(suffix) ||
		!strings.HasPrefix(got, prefix) || !strings.HasSuffix(got, suffix) {
		return false
	}
	mid := got[len(prefix) : len(got)-len(suffix)]
	return mid != "" && !strings.Contains(mid, "/")
}

// discover returns the provider's discovery document, cached for an hour.
// Failures are not cached.
func (p *Plugin) discover(ctx context.Context, pr *provider) (*metadata, error) {
	key := pr.cfg.Name
	p.discMu.Lock()
	c, ok := p.disc[key]
	p.discMu.Unlock()
	if ok && time.Since(c.fetched) < discoveryTTL {
		return c.meta, nil
	}

	md, err := p.fetchMetadata(ctx, pr)
	if err != nil {
		return nil, err
	}
	p.discMu.Lock()
	if p.disc == nil {
		p.disc = map[string]cachedMeta{}
	}
	p.disc[key] = cachedMeta{meta: md, fetched: time.Now()}
	p.discMu.Unlock()
	return md, nil
}

func (p *Plugin) fetchMetadata(ctx context.Context, pr *provider) (*metadata, error) {
	u := strings.TrimRight(pr.issuerOf(), "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("oauth: discovery for %q: %w", pr.cfg.Name, err)
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth: discovery for %q: %w", pr.cfg.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth: discovery for %q: status %d", pr.cfg.Name, resp.StatusCode)
	}
	var md metadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&md); err != nil {
		return nil, fmt.Errorf("oauth: discovery for %q: %w", pr.cfg.Name, err)
	}
	if !issuerMatches(pr, md.Issuer) {
		return nil, fmt.Errorf("oauth: discovery for %q: issuer does not match", pr.cfg.Name)
	}
	// The token endpoint gets the client secret, the others a code or a token:
	// none of them in clear text. Userinfo and revocation are optional.
	for _, e := range []struct {
		name, url string
		optional  bool
	}{
		{"authorization_endpoint", md.AuthorizationEndpoint, false},
		{"token_endpoint", md.TokenEndpoint, false},
		{"userinfo_endpoint", md.UserinfoEndpoint, true},
		{"revocation_endpoint", md.RevocationEndpoint, true},
	} {
		if e.url == "" && e.optional {
			continue
		}
		if !secureURL(e.url) {
			return nil, fmt.Errorf("oauth: discovery for %q: %s is not https (or http to loopback)", pr.cfg.Name, e.name)
		}
	}
	return &md, nil
}

// secureURL reports whether raw is an absolute URL with a host that may carry a
// secret: https, or http to loopback (see clearTextOK).
func secureURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && clearTextOK(u)
}
