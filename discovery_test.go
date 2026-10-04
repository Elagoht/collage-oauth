package oauth

import (
	"context"
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
		fp := newFakeProvider(t)
		fp.Issuer = issuer
		p, pr := discoveryPlugin(t, fp, spec)
		_, err := p.discover(context.Background(), pr)
		if (err == nil) != ok {
			t.Errorf("issuer %q: err = %v, want ok=%v", issuer, err, ok)
		}
	}
}
