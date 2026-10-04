package oauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestEndToEnd is the whole flow: login, the provider's side, the callback, a
// guarded page, an API call with the reader's token, logout, the guard again.
func TestEndToEnd(t *testing.T) {
	s := newSiteApp(t, `<a href="{{oauthLogin "test"}}">x</a>`, func(o *Options) {
		o.Providers[0].Offline = true
	})

	// 0. Signed out: the guard sends the reader away.
	if res := s.c.Get("/panel").WantStatus(http.StatusSeeOther); !strings.HasPrefix(res.Location(), "/login?") {
		t.Fatalf("guard sent to %q", res.Location())
	}

	// 1. The page's link leads to login, and login to the provider.
	page := s.c.Get("/blog").WantStatus(http.StatusOK)
	login := s.c.Get(href(t, page.Body)).WantStatus(http.StatusSeeOther)
	authz, err := url.Parse(login.Location())
	if err != nil {
		t.Fatal(err)
	}
	if want := s.f.URL + "/authorize"; !strings.HasPrefix(login.Location(), want) {
		t.Fatalf("login went to %q, want %s...", login.Location(), want)
	}
	q := authz.Query()
	for _, k := range []string{"state", "nonce", "code_challenge", "redirect_uri"} {
		if q.Get(k) == "" {
			t.Errorf("authorization request has no %s", k)
		}
	}

	// 2. The provider authenticates the reader and sends them back with a code.
	s.f.ExpectCode("c1", q.Get("nonce"))
	s.f.RememberChallenge("c1", q.Get("code_challenge"))
	s.f.ExpectRedirectURI("c1", q.Get("redirect_uri"))

	// 3. The callback signs the reader in and sends them to next.
	cb := s.c.Get("/auth/test/callback?code=c1&state=" + url.QueryEscape(q.Get("state"))).WantStatus(http.StatusSeeOther)
	if got := cb.Location(); got != "/blog" {
		t.Errorf("callback went to %q, want /blog", got)
	}

	// 4. The guarded page is reachable.
	s.c.Get("/panel").WantStatus(http.StatusOK)

	// 5. Client calls the provider's API with the access token.
	cl, err := s.p.Client(context.Background(), "app-user", "test")
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	if got, err := callAPI(cl, s.f.URL); err != nil || got != "Bearer access-c1" {
		t.Errorf("API saw %q, %v; want Bearer access-c1", got, err)
	}
	if blob := s.st.row("app-user", "test"); blob == nil || strings.Contains(string(blob), "access-c1") {
		t.Errorf("store holds %q: want a sealed row", blob)
	}

	// 6. The application's logout action clears the session.
	s.c.Get("/logout").WantStatus(http.StatusSeeOther)

	// 7. The guard sends the reader to login again.
	if res := s.c.Get("/panel").WantStatus(http.StatusSeeOther); !strings.HasPrefix(res.Location(), "/login?") {
		t.Errorf("after logout the guard sent to %q", res.Location())
	}
}
