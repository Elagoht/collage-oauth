package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	session "github.com/Elagoht/collage-session"
	"github.com/Elagoht/collage/pkg/collage"
	"github.com/Elagoht/collage/pkg/collagetest"
)

// peekPlugin mounts /peek, which answers the pending sign-in the request's
// session holds for the provider "test", as JSON; 404 when there is none.
type peekPlugin struct{ p *Plugin }

func (peekPlugin) Name() string                   { return "test/peek" }
func (peekPlugin) Version() string                { return "0" }
func (peekPlugin) Shutdown(context.Context) error { return nil }
func (k peekPlugin) Init(_ context.Context, host collage.Host) error {
	return host.Handle("/peek", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pd, ok := k.p.pendingFor(r, "test")
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(pd)
	}))
}

// hostOrigins maps the host a.test to https://a.example.
type hostOrigins struct{}

func (hostOrigins) Name() string                   { return "test/origins" }
func (hostOrigins) Version() string                { return "0" }
func (hostOrigins) Shutdown(context.Context) error { return nil }
func (hostOrigins) Init(context.Context, collage.Host) error {
	return nil
}
func (hostOrigins) Origin(_ context.Context, host string) (string, bool) {
	if host == "a.test" {
		return "https://a.example", true
	}
	return "", false
}

type loginApp struct {
	c *collagetest.Client
	p *Plugin
	f *fakeProvider
}

// newLoginApp builds a development-mode app; the redirect URI then falls back to
// the request's own host.
func newLoginApp(t *testing.T, withSession bool, extra ...collage.Plugin) loginApp {
	t.Helper()
	return newLoginAppCfg(t, withSession, func(cfg *collage.Config) { cfg.DevMode = true }, extra...)
}

func newLoginAppCfg(t *testing.T, withSession bool, mod func(*collage.Config), extra ...collage.Plugin) loginApp {
	t.Helper()
	fp := newFakeProvider(t)
	p := New(Options{
		Providers: []Provider{{Name: "test", Issuer: fp.URL, ClientID: "client", ClientSecret: "secret"}},
		OnLogin:   func(context.Context, Identity) (string, error) { return "u", nil },

		HTTPClient: fp.Client,
	})
	var plugins []collage.Plugin
	if withSession {
		plugins = append(plugins, session.New(session.Options{KeyHex: strings.Repeat("ab", 32)}))
	}
	plugins = append(plugins, extra...)
	plugins = append(plugins, p, peekPlugin{p})
	cfg := &collage.Config{
		Server:   collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{"t/x.html": {Data: []byte("x")}}, Root: "t"},
		Plugins:  plugins,
	}
	mod(cfg)
	app, err := collage.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	return loginApp{c: collagetest.New(t, app.Handler()), p: p, f: fp}
}

func (a loginApp) peek(t *testing.T, base string) pending {
	t.Helper()
	res := a.c.Get(base + "/peek").WantStatus(http.StatusOK)
	return decodePending(t, res.Body)
}

func TestLogin_RedirectsToTheProviderWithPKCE(t *testing.T) {
	a := newLoginApp(t, true)
	res := a.c.Get("/auth/test/login?next=/panel").WantStatus(http.StatusSeeOther)
	loc := res.Location()
	if !strings.HasPrefix(loc, a.f.URL+"/authorize?") {
		t.Fatalf("Location = %q", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	want := map[string]string{
		"response_type":         "code",
		"client_id":             "client",
		"scope":                 "openid email profile",
		"code_challenge_method": "S256",
		"redirect_uri":          "http://example.com/auth/test/callback",
	}
	for k, v := range want {
		if got := q.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	pd := a.peek(t, "")
	if pd.State == "" || pd.State != q.Get("state") {
		t.Errorf("state %q in the URL, %q in the session", q.Get("state"), pd.State)
	}
	if pd.Nonce == "" || pd.Nonce != q.Get("nonce") {
		t.Errorf("nonce %q in the URL, %q in the session", q.Get("nonce"), pd.Nonce)
	}
	if pd.Verifier == "" || q.Get("code_challenge") != challenge(pd.Verifier) {
		t.Errorf("code_challenge %q does not match the stored verifier", q.Get("code_challenge"))
	}
	if pd.State == pd.Nonce || pd.Nonce == pd.Verifier || pd.State == pd.Verifier {
		t.Error("state, nonce and verifier must be independent")
	}
	if pd.Next != "/panel" || pd.Created == 0 {
		t.Errorf("pending = %+v", pd)
	}
	if challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Error("challenge is not the RFC 7636 S256 transform")
	}
}

func TestLogin_UnsafeNextBecomesAfterLogin(t *testing.T) {
	for _, next := range []string{"//evil.com", `/\evil.com`, "https://evil.com", "javascript:x", `/./\evil.com`, `/a/../\evil.com`} {
		a := newLoginApp(t, true)
		a.c.Get("/auth/test/login?next=" + url.QueryEscape(next)).WantStatus(http.StatusSeeOther)
		if got := a.peek(t, "").Next; got != "/" {
			t.Errorf("next=%q stored %q, want /", next, got)
		}
	}
}

func TestLogin_AgainReplacesThePending(t *testing.T) {
	a := newLoginApp(t, true)
	a.c.Get("/auth/test/login").WantStatus(http.StatusSeeOther)
	first := a.peek(t, "")
	a.c.Get("/auth/test/login").WantStatus(http.StatusSeeOther)
	if second := a.peek(t, ""); second.State == first.State {
		t.Error("a second login kept the first's state")
	}
}

func TestLogin_OfflineParameters(t *testing.T) {
	cases := map[string]struct {
		preset  string
		wantQ   url.Values
		wantOff bool
	}{
		"google":    {"google", url.Values{"access_type": {"offline"}, "prompt": {"consent"}}, false},
		"microsoft": {"microsoft", nil, true},
		"gitlab":    {"gitlab", nil, false},
		// A custom issuer is standard OpenID Connect: offline_access asks for
		// the refresh token.
		"no preset": {"", nil, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := newLoginApp(t, true)
			pr := a.p.providers["test"]
			pr.cfg.Offline = true
			pr.cfg.Scopes = []string{"calendar"}
			pr.cfg.Preset, pr.preset = tc.preset, presets[tc.preset]
			res := a.c.Get("/auth/test/login").WantStatus(http.StatusSeeOther)
			u, _ := url.Parse(res.Location())
			q := u.Query()
			for k := range tc.wantQ {
				if q.Get(k) != tc.wantQ.Get(k) {
					t.Errorf("%s = %q, want %q", k, q.Get(k), tc.wantQ.Get(k))
				}
			}
			if tc.wantQ == nil && (q.Has("access_type") || q.Has("prompt")) {
				t.Errorf("unexpected offline parameters in %q", res.Location())
			}
			scopes := strings.Fields(q.Get("scope"))
			has := false
			for _, s := range scopes {
				has = has || s == "offline_access"
			}
			if has != tc.wantOff {
				t.Errorf("offline_access in %v = %v, want %v", scopes, has, tc.wantOff)
			}
			if !strings.Contains(q.Get("scope"), "openid email profile calendar") {
				t.Errorf("scope = %q lost the base or the provider's scopes", q.Get("scope"))
			}
		})
	}
}

func TestLogin_NoOfflineParametersWithoutOffline(t *testing.T) {
	a := newLoginApp(t, true)
	a.p.providers["test"].preset = presets["microsoft"]
	res := a.c.Get("/auth/test/login").WantStatus(http.StatusSeeOther)
	u, _ := url.Parse(res.Location())
	if strings.Contains(u.Query().Get("scope"), "offline_access") {
		t.Errorf("scope = %q", u.Query().Get("scope"))
	}
}

func TestLogin_UnknownProviderOrPathIs404(t *testing.T) {
	a := newLoginApp(t, true)
	for _, path := range []string{"/auth/nope/login", "/auth/test/other", "/auth/test", "/auth/test/login/x", "/auth/"} {
		a.c.Get(path).WantStatus(http.StatusNotFound)
	}
}

func TestLogin_WithoutTheSessionPluginIs500(t *testing.T) {
	a := newLoginApp(t, false)
	a.c.Get("/auth/test/login").WantStatus(http.StatusInternalServerError)
}

func TestLogin_RedirectURIFollowsTheHost(t *testing.T) {
	a := newLoginApp(t, true, hostOrigins{})
	res := a.c.Get("http://a.test/auth/test/login").WantStatus(http.StatusSeeOther)
	u, _ := url.Parse(res.Location())
	if got := u.Query().Get("redirect_uri"); got != "https://a.example/auth/test/callback" {
		t.Errorf("redirect_uri = %q", got)
	}
}

func TestLogin_DiscoveryFailureIsFailed(t *testing.T) {
	a := newLoginApp(t, true)
	a.f.DiscoveryStatus = http.StatusInternalServerError
	a.c.Get("/auth/test/login").WantStatus(http.StatusServiceUnavailable)
}

func TestFail_ErrorPathRedirects(t *testing.T) {
	a := newLoginApp(t, true)
	a.p.opts.ErrorPath = "/sign-in-failed"
	a.f.DiscoveryStatus = http.StatusInternalServerError
	res := a.c.Get("/auth/test/login").WantStatus(http.StatusSeeOther)
	if got := res.Location(); got != "/sign-in-failed?error=unavailable" {
		t.Errorf("Location = %q", got)
	}
}

func decodePending(t *testing.T, body string) pending {
	t.Helper()
	var pd pending
	if err := json.Unmarshal([]byte(body), &pd); err != nil {
		t.Fatalf("pending: %v", err)
	}
	return pd
}

func TestLogin_RedirectURIOutsideDevelopment(t *testing.T) {
	t.Run("no origin is 500", func(t *testing.T) {
		a := newLoginAppCfg(t, true, func(*collage.Config) {})
		a.c.Get("/auth/test/login").WantStatus(http.StatusInternalServerError)
	})
	t.Run("BaseURL is used", func(t *testing.T) {
		a := newLoginAppCfg(t, true, func(cfg *collage.Config) { cfg.BaseURL = "https://site.example" })
		res := a.c.Get("/auth/test/login").WantStatus(http.StatusSeeOther)
		u, _ := url.Parse(res.Location())
		if got := u.Query().Get("redirect_uri"); got != "https://site.example/auth/test/callback" {
			t.Errorf("redirect_uri = %q", got)
		}
	})
}

func TestLogin_LongNextIsDropped(t *testing.T) {
	a := newLoginApp(t, true)
	a.c.Get("/auth/test/login?next=/" + strings.Repeat("a", 2000)).WantStatus(http.StatusSeeOther)
	if got := a.peek(t, "").Next; got != "/" {
		t.Errorf("a 2000-byte next stored %d bytes, want AfterLogin", len(got))
	}
	a.c.Get("/auth/test/login?next=/" + strings.Repeat("a", 1023)).WantStatus(http.StatusSeeOther)
	if got := a.peek(t, "").Next; len(got) != 1024 {
		t.Errorf("a 1024-byte next stored %d bytes, want it kept", len(got))
	}
}

func TestFail_ErrorPathKeepsItsQuery(t *testing.T) {
	a := newLoginApp(t, true)
	a.p.opts.ErrorPath = "/oops?x=1"
	a.f.DiscoveryStatus = http.StatusInternalServerError
	res := a.c.Get("/auth/test/login").WantStatus(http.StatusSeeOther)
	if got := res.Location(); got != "/oops?error=unavailable&x=1" {
		t.Errorf("Location = %q", got)
	}
}

func TestLogin_OnlyGETTouchesTheSignIn(t *testing.T) {
	a := newLoginApp(t, true)
	a.c.Get("/auth/test/login").WantStatus(http.StatusSeeOther)
	before := a.peek(t, "")
	for _, method := range []string{http.MethodHead, http.MethodPost} {
		for _, route := range []string{"login", "callback"} {
			res := a.c.Do(a.c.Request(method, "/auth/test/"+route, nil)).WantStatus(http.StatusMethodNotAllowed)
			if res.Header.Get("Allow") != "GET" {
				t.Errorf("%s %s: Allow = %q", method, route, res.Header.Get("Allow"))
			}
		}
	}
	if after := a.peek(t, ""); after != before {
		t.Errorf("pending changed: %+v -> %+v", before, after)
	}
}

// The redirects login and fail write carry the Location and no body, and fail
// sends ErrorPath as configured, uncleaned.
func TestLogin_RedirectsAreWrittenRaw(t *testing.T) {
	a := newLoginApp(t, true)
	res := a.c.Get("/auth/test/login").WantStatus(http.StatusSeeOther)
	if res.Body != "" {
		t.Errorf("login: body %q, want none", res.Body)
	}
	b := newLoginApp(t, true)
	b.p.opts.ErrorPath = "/oops/./x"
	b.f.DiscoveryStatus = http.StatusInternalServerError
	res = b.c.Get("/auth/test/login").WantStatus(http.StatusSeeOther)
	if got := res.Location(); got != "/oops/./x?error=unavailable" {
		t.Errorf("fail: Location = %q", got)
	}
	if res.Body != "" {
		t.Errorf("fail: body %q, want none", res.Body)
	}
}

// The pending sign-in is JSON without HTML escapes: "<" stays one byte, so an
// escape-heavy next does not grow the session cookie sixfold.
func TestPending_EncodedWithoutHTMLEscapes(t *testing.T) {
	raw, err := encodePending(pending{Next: "/<a>&b"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, `"/<a>&b"`) || strings.HasSuffix(raw, "\n") {
		t.Errorf("encoded %q", raw)
	}
	if got := decodePending(t, raw); got.Next != "/<a>&b" {
		t.Errorf("round trip gave %q", got.Next)
	}
}

// A next within the 1024-byte cap that the session still cannot hold ends at
// AfterLogin rather than in a 500.
func TestLogin_NextTooLargeForTheSessionEndsAtAfterLogin(t *testing.T) {
	t.Run("escape-heavy next", func(t *testing.T) {
		a := newLoginApp(t, true)
		a.c.Get("/auth/test/login?next=" + url.QueryEscape("/"+strings.Repeat("<", 1023))).WantStatus(http.StatusSeeOther)
		if got := a.peek(t, "").Next; got != "/" {
			t.Errorf("stored a %d-byte next, want AfterLogin", len(got))
		}
	})
	t.Run("session near its limit", func(t *testing.T) {
		a := newLoginApp(t, true, sidPlugin{})
		a.c.Get("/kv?k=fill&v=" + strings.Repeat("x", 2000)).WantStatus(http.StatusOK)
		a.c.Get("/auth/test/login?next=/" + strings.Repeat("a", 1000)).WantStatus(http.StatusSeeOther)
		if got := a.peek(t, "").Next; got != "/" {
			t.Errorf("stored a %d-byte next, want AfterLogin", len(got))
		}
		if got := a.c.Get("/kv?k=fill").Body; len(got) != 2000 {
			t.Errorf("the session lost its own data: %d bytes", len(got))
		}
	})
}
