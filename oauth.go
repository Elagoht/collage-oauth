// Package oauth signs a reader in with an OpenID Connect provider through
// elagoht/session, and keeps the provider's API tokens sealed and refreshed.
package oauth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Elagoht/collage/pkg/collage"
)

// Name is the plugin's name.
const Name = "elagoht/oauth"

// provider is a configured Provider, with its secret resolved.
type provider struct {
	cfg    Provider
	secret string
	preset presetSpec
}

// Plugin is the oauth plugin.
type Plugin struct {
	opts      Options
	providers map[string]*provider
	keys      [][]byte // Key first, then PreviousKeys
	host      collage.Host

	discMu sync.Mutex
	disc   map[string]cachedMeta // discovery documents by provider name

	tok tokenState // opened tokens, refreshes in flight, revocations; see client.go

	now func() time.Time // the clock; nil is time.Now. Tests set it.
}

// clock is the time now, by the plugin's clock.
func (p *Plugin) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// New returns the plugin.
func New(opts Options) *Plugin { return &Plugin{opts: opts} }

// Name returns Name.
func (p *Plugin) Name() string { return Name }

// Version returns the plugin's version.
func (p *Plugin) Version() string { return "0.1.0" }

var errBadHex = errors.New("oauth: key is not valid hex")

func decodeKey(s string) ([]byte, error) {
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, errBadHex
	}
	return key, nil
}

// Configure reads the configuration, checks it, and reserves {{oauthLogin}}.
func (p *Plugin) Configure(_ context.Context, host collage.ConfigHost) error {
	if err := host.Config(&p.opts); err != nil {
		return err
	}
	o := &p.opts
	if o.Prefix == "" {
		o.Prefix = "/auth"
	}
	if !strings.HasPrefix(o.Prefix, "/") {
		return fmt.Errorf("oauth: prefix %q must start with /", o.Prefix)
	}
	o.Prefix = strings.TrimRight(o.Prefix, "/")
	if o.Prefix == "" {
		return errors.New("oauth: prefix must name a path below /")
	}
	if o.ErrorPath != "" && collage.SafeRedirect(o.ErrorPath, "") != o.ErrorPath {
		return errors.New("oauth: errorPath must be a path on this site, starting with a single /")
	}
	if o.AfterLogin == "" {
		o.AfterLogin = "/"
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if o.OnLogin == nil {
		return errors.New("oauth: OnLogin is required")
	}

	if o.KeyHex != "" {
		key, err := decodeKey(o.KeyHex)
		if err != nil {
			return err
		}
		o.Key = key
	}
	if len(o.Key) > 0 && len(o.Key) < 32 {
		return errors.New("oauth: key must be at least 32 bytes")
	}
	if o.Store != nil && len(o.Key) == 0 {
		return errors.New("oauth: Store needs a key to seal tokens with")
	}
	previous := o.PreviousKeys
	for _, h := range o.PreviousKeysHex {
		key, err := decodeKey(h)
		if err != nil {
			return err
		}
		previous = append(previous[:len(previous):len(previous)], key)
	}
	for _, key := range previous {
		if len(key) < 32 {
			return errors.New("oauth: a previous key must be at least 32 bytes")
		}
	}
	p.keys = nil
	if len(o.Key) > 0 {
		p.keys = append(p.keys, o.Key)
		p.keys = append(p.keys, previous...)
	}

	if len(o.Providers) == 0 {
		return errors.New("oauth: no providers")
	}
	p.providers = make(map[string]*provider, len(o.Providers))
	for _, cfg := range o.Providers {
		pr, err := resolveProvider(cfg)
		if err != nil {
			return err
		}
		if _, dup := p.providers[cfg.Name]; dup {
			return fmt.Errorf("oauth: provider %q is declared twice", cfg.Name)
		}
		p.providers[cfg.Name] = pr
	}

	return host.AddRenderFunc("oauthLogin", func(rc *collage.RenderContext) any { // any: html/template.FuncMap's own value type
		return func(name string, next ...string) (string, error) {
			if p.providers[name] == nil {
				return "", fmt.Errorf("oauthLogin: unknown provider %q", name)
			}
			to := p.opts.AfterLogin
			if rc != nil && rc.Request != nil {
				to = rc.Request.URL.RequestURI()
			}
			if len(next) > 0 {
				to = next[0]
			}
			return p.opts.Prefix + "/" + name + "/login?next=" + url.QueryEscape(to), nil
		}
	})
}

func resolveProvider(cfg Provider) (*provider, error) {
	if cfg.Name == "" {
		return nil, errors.New("oauth: a provider has no name")
	}
	if strings.ContainsAny(cfg.Name, "/?#") || strings.IndexFunc(cfg.Name, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, fmt.Errorf("oauth: provider name %q must be one URL segment without control characters", cfg.Name)
	}
	pr := &provider{cfg: cfg}
	if cfg.Preset != "" {
		spec, ok := presets[cfg.Preset]
		if !ok {
			return nil, fmt.Errorf("oauth: provider %q: unknown preset %q", cfg.Name, cfg.Preset)
		}
		pr.preset = spec
	} else if cfg.Issuer == "" {
		return nil, fmt.Errorf("oauth: provider %q needs a preset or an issuer", cfg.Name)
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("oauth: provider %q has no clientID", cfg.Name)
	}
	switch {
	case cfg.ClientSecretEnv != "":
		pr.secret = os.Getenv(cfg.ClientSecretEnv)
		if pr.secret == "" {
			return nil, fmt.Errorf("oauth: provider %q: environment variable %s is unset or empty", cfg.Name, cfg.ClientSecretEnv)
		}
	case cfg.ClientSecret != "":
		pr.secret = cfg.ClientSecret
	default:
		return nil, fmt.Errorf("oauth: provider %q has no client secret", cfg.Name)
	}
	return pr, nil
}

// Init mounts the routes.
func (p *Plugin) Init(_ context.Context, host collage.Host) error {
	if p.providers == nil {
		return errors.New("oauth: register the plugin in Config.Plugins, where Configure runs")
	}
	p.host = host
	return host.Handle(p.opts.Prefix+"/", p)
}

// Shutdown does nothing yet.
func (p *Plugin) Shutdown(context.Context) error { return nil }

// ServeHTTP dispatches {prefix}/{name}/login and {prefix}/{name}/callback. An
// unknown provider or path gets the 404 page, a method other than GET the 405 page.
func (p *Plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, route, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, p.opts.Prefix+"/"), "/")
	pr := p.providers[name]
	if !ok || pr == nil || (route != "login" && route != "callback") {
		p.host.ServeStatus(w, r, http.StatusNotFound)
		return
	}
	// GET only: a HEAD (a link preview) must not mint or spend a pending sign-in.
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		p.host.ServeStatus(w, r, http.StatusMethodNotAllowed)
		return
	}
	switch route {
	case "login":
		p.login(w, r, name, pr)
	case "callback":
		p.callback(w, r, name, pr)
	default:
		p.host.ServeStatus(w, r, http.StatusNotFound)
	}
}
