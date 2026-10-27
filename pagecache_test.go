package oauth

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	session "github.com/Elagoht/collage-session"
	"github.com/Elagoht/collage/pkg/collage"
	"github.com/Elagoht/collage/pkg/collagetest"
)

// PLUGA-03: an anonymous GET to the login route kept the pending sign-in in
// the session, which started it: a signed, week-long session cookie that turns
// the page cache off, one GET away for anybody. The pending sign-in now lives
// in a short cookie of its own, scoped to the provider's routes, and no session
// is started before a successful callback.
func TestLogin_MintsNoCacheBypassingSession(t *testing.T) {
	fp := newFakeProvider(t)
	var renders atomic.Int64
	expensive := collage.NewFragment("a", "a.html").WithData(collage.Load(
		func(context.Context, *collage.RenderContext) (int64, error) { return renders.Add(1), nil })).Build()
	home := collage.NewPage("home").WithContent(expensive).WithPath("en", "/").Incremental(time.Hour).Build()
	site := collagetest.NewSite(t,
		collagetest.WithoutHome(),
		collagetest.WithPlugins(
			session.New(session.Options{Key: bytes.Repeat([]byte{0xab}, 32)}),
			New(Options{
				Providers:  []Provider{{Name: "test", Issuer: fp.URL, ClientID: "client", ClientSecret: "secret"}},
				OnLogin:    func(context.Context, Identity) (string, error) { return "u", nil },
				HTTPClient: fp.Client,
			}),
		),
		collagetest.WithTemplates(map[string]string{"a.html": `<p>{{.}}</p>`}),
		collagetest.WithRegister(home),
		collagetest.WithConfig(func(c *collage.Config) {
			c.BaseURL = "https://site.example"
			c.Cache = collage.CacheConfig{Enabled: true, Type: "memory", DefaultTTL: time.Hour}
		}),
	)
	h := site.App.Handler()
	get := func(target string, cookies []*http.Cookie) *http.Response {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Result()
	}
	get("https://site.example/", nil)

	res := get("https://site.example/auth/test/login", nil)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("login answered %d", res.StatusCode)
	}
	cookies := res.Cookies()
	for _, c := range cookies {
		if c.Name == "collage_session" {
			t.Fatalf("an anonymous login started a session: %s (Max-Age %d)", c.Name, c.MaxAge)
		}
	}
	var pendingCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == pendingCookieName {
			pendingCookie = c
		}
	}
	if pendingCookie == nil {
		t.Fatalf("login set no %s cookie: %v", pendingCookieName, cookies)
	}
	if pendingCookie.Path != "/auth/test/" || !pendingCookie.HttpOnly || pendingCookie.SameSite != http.SameSiteLaxMode ||
		!pendingCookie.Secure || pendingCookie.MaxAge <= 0 || pendingCookie.MaxAge > int(pendingTTL/time.Second) {
		t.Errorf("pending cookie = %+v, want Path=/auth/test/ HttpOnly SameSite=Lax Secure, Max-Age at most %v", pendingCookie, pendingTTL)
	}

	// Every cookie the login set, replayed on a cached page, path or not.
	const n = 50
	for range n {
		get("https://site.example/", cookies)
	}
	if got := renders.Load(); got != 1 {
		t.Fatalf("%d renders of an Incremental page with the login's cookies replayed %d times, want 1 (cached)", got, n)
	}
}

// setCookies are the cookies res sets.
func setCookies(res *collagetest.Response) []*http.Cookie {
	return (&http.Response{Header: res.Header}).Cookies()
}

// The callback deletes the pending cookie whatever its outcome, and a failed
// one leaves the reader with no session either: only a successful callback
// starts one.
func TestCallback_DeletesThePendingCookie(t *testing.T) {
	for _, succeed := range []bool{true, false} {
		a := newCallbackApp(t, "", nil)
		state := a.login(t, "c1")
		if !succeed {
			state = "wrong"
		}
		res := a.callback("c1", state)
		deleted, session := false, false
		for _, c := range setCookies(res) {
			if c.Name == pendingCookieName && c.Path == "/auth/test/" && c.MaxAge < 0 {
				deleted = true
			}
			if c.Name == "collage_session" && c.MaxAge > 0 {
				session = true
			}
		}
		if !deleted {
			t.Errorf("succeed=%v: the callback did not delete the pending cookie: %v", succeed, res.Header.Values("Set-Cookie"))
		}
		if session != succeed {
			t.Errorf("succeed=%v: session cookie set = %v", succeed, session)
		}
	}
}

// Over plain http in development the pending cookie is not Secure, or the
// browser would not send it back.
func TestLogin_PendingCookieOverHTTP(t *testing.T) {
	a := newLoginApp(t, true)
	res := a.c.Get("/auth/test/login").WantStatus(http.StatusSeeOther)
	for _, c := range setCookies(res) {
		if c.Name == pendingCookieName && c.Secure {
			t.Errorf("pending cookie is Secure over http")
		}
	}
}
