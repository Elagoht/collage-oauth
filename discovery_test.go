package oauth

import (
	"context"
	"net/http"
	"testing"
)

func discoveryPlugin(t *testing.T, fp *fakeProvider, preset presetSpec) (*Plugin, *provider) {
	t.Helper()
	p := &Plugin{opts: Options{HTTPClient: fp.Client}}
	pr := &provider{
		cfg:    Provider{Name: "fake", Issuer: fp.URL, ClientID: "client"},
		secret: "secret",
		preset: preset,
	}
	return p, pr
}

func TestDiscover_CachedForAnHour(t *testing.T) {
	fp := newFakeProvider(t)
	p, pr := discoveryPlugin(t, fp, presetSpec{})
	for range 2 {
		md, err := p.discover(context.Background(), pr)
		if err != nil {
			t.Fatal(err)
		}
		if md.TokenEndpoint != fp.URL+"/token" || md.AuthorizationEndpoint != fp.URL+"/authorize" ||
			md.UserinfoEndpoint != fp.URL+"/userinfo" || md.RevocationEndpoint != fp.URL+"/revoke" ||
			len(md.TokenAuthMethods) != 1 || md.TokenAuthMethods[0] != "client_secret_basic" {
			t.Fatalf("metadata = %+v", md)
		}
	}
	if n := fp.DiscoveryCalls.Load(); n != 1 {
		t.Fatalf("DiscoveryCalls = %d, want 1", n)
	}
}

func TestDiscover_IssuerMismatchFails(t *testing.T) {
	fp := newFakeProvider(t)
	fp.Issuer = "https://evil.example"
	p, pr := discoveryPlugin(t, fp, presetSpec{})
	if _, err := p.discover(context.Background(), pr); err == nil {
		t.Fatal("a document with another issuer was accepted")
	}
}

func TestDiscover_FailureIsNotCached(t *testing.T) {
	fp := newFakeProvider(t)
	fp.DiscoveryStatus = 500
	p, pr := discoveryPlugin(t, fp, presetSpec{})
	if _, err := p.discover(context.Background(), pr); err == nil {
		t.Fatal("a 500 was accepted")
	}
	fp.DiscoveryStatus = 0
	if _, err := p.discover(context.Background(), pr); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if n := fp.DiscoveryCalls.Load(); n != 2 {
		t.Fatalf("DiscoveryCalls = %d, want 2", n)
	}
}

func TestDiscover_Unreachable(t *testing.T) {
	fp := newFakeProvider(t)
	p, pr := discoveryPlugin(t, fp, presetSpec{})
	pr.cfg.Issuer = "https://127.0.0.1:1"
	if _, err := p.discover(context.Background(), pr); err == nil {
		t.Fatal("an unreachable issuer was accepted")
	}
}

func TestDiscover_MicrosoftTemplate(t *testing.T) {
	spec := presets["microsoft"]
	for issuer, ok := range map[string]bool{
		"https://login.microsoftonline.com/abc/v2.0":    true,
		"https://login.microsoftonline.com/common/v2.0": true,
		"https://login.microsoftonline.com//v2.0":       false,
		"https://login.microsoftonline.com/a/b/v2.0":    false,
		"https://login.microsoftonline.com/abc/v3.0":    false,
	} {
		pr := &provider{cfg: Provider{Name: "ms", Preset: "microsoft"}, preset: spec}
		if got := issuerMatches(pr, issuer); got != ok {
			t.Errorf("issuer %q: match = %v, want %v", issuer, got, ok)
		}
	}
}

// A configured Issuer is one tenant: the "common" template no longer applies, so
// another tenant's iss is refused, in discovery and in the id_token.
func TestDiscover_TenantIssuerIsExact(t *testing.T) {
	const tenant = "https://login.microsoftonline.com/tenant-a/v2.0"
	pr := &provider{cfg: Provider{Name: "ms", Preset: "microsoft", Issuer: tenant}, preset: presets["microsoft"]}
	for issuer, ok := range map[string]bool{
		tenant: true,
		"https://login.microsoftonline.com/tenant-b/v2.0": false,
		"https://login.microsoftonline.com/common/v2.0":   false,
	} {
		if got := issuerMatches(pr, issuer); got != ok {
			t.Errorf("issuer %q: match = %v, want %v", issuer, got, ok)
		}
	}

	fp := newFakeProvider(t)
	fp.Issuer = "https://login.microsoftonline.com/tenant-b/v2.0"
	p, pr2 := discoveryPlugin(t, fp, presets["microsoft"])
	pr2.cfg.Preset = "microsoft"
	if _, err := p.discover(context.Background(), pr2); err == nil {
		t.Error("discovery for a configured issuer accepted another tenant's document")
	}
}

// Every endpoint discovery names must be https, or http to loopback: the token
// endpoint gets the client secret, the others a code or a token.
func TestDiscover_EndpointsMustNotBeClearText(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(d *fakeDiscovery)
		ok   bool
	}{
		"http token endpoint":             {func(d *fakeDiscovery) { d.TokenEndpoint = "http://idp.example/token" }, false},
		"http authorization endpoint":     {func(d *fakeDiscovery) { d.AuthorizationEndpoint = "http://idp.example/authorize" }, false},
		"http userinfo endpoint":          {func(d *fakeDiscovery) { d.UserinfoEndpoint = "http://idp.example/userinfo" }, false},
		"http revocation endpoint":        {func(d *fakeDiscovery) { d.RevocationEndpoint = "http://idp.example/revoke" }, false},
		"no token endpoint":               {func(d *fakeDiscovery) { d.TokenEndpoint = "" }, false},
		"no authorization endpoint":       {func(d *fakeDiscovery) { d.AuthorizationEndpoint = "" }, false},
		"http token endpoint on loopback": {func(d *fakeDiscovery) { d.TokenEndpoint = "http://127.0.0.1:9/token" }, true},
		"no userinfo or revocation":       {func(d *fakeDiscovery) { d.UserinfoEndpoint, d.RevocationEndpoint = "", "" }, true},
	} {
		t.Run(name, func(t *testing.T) {
			fp := newFakeProvider(t)
			fp.Discovery = tc.edit
			p, pr := discoveryPlugin(t, fp, presetSpec{})
			_, err := p.discover(context.Background(), pr)
			if (err == nil) != tc.ok {
				t.Errorf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// A clear-text endpoint ends a sign-in as unavailable.
func TestLogin_ClearTextEndpointIsUnavailable(t *testing.T) {
	a := newLoginApp(t, true)
	a.f.Discovery = func(d *fakeDiscovery) { d.TokenEndpoint = "http://idp.example/token" }
	a.c.Get("/auth/test/login").WantStatus(http.StatusServiceUnavailable)
}
