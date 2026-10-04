package oauth

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	session "github.com/Elagoht/collage-session"
	"github.com/Elagoht/collage/pkg/collage"
	"github.com/Elagoht/collage/pkg/collagetest"
)

// sidPlugin mounts /sid, which answers the request's session ID.
type sidPlugin struct{}

func (sidPlugin) Name() string                   { return "test/sid" }
func (sidPlugin) Version() string                { return "0" }
func (sidPlugin) Shutdown(context.Context) error { return nil }
func (sidPlugin) Init(_ context.Context, host collage.Host) error {
	if err := host.Handle("/sid", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, session.FromContext(r.Context()).ID())
	})); err != nil {
		return err
	}
	// /kv?k=key answers the session's value; /kv?k=key&v=value sets it first.
	return host.Handle("/kv", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, q := session.FromContext(r.Context()), r.URL.Query()
		if q.Has("v") {
			if err := s.Set(q.Get("k"), q.Get("v")); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		_, _ = io.WriteString(w, s.Get(q.Get("k")))
	}))
}

type callbackApp struct {
	c      *collagetest.Client
	h      http.Handler
	p      *Plugin
	f      *fakeProvider
	logins []Identity
}

// newCallbackApp builds a development-mode app with session, the oauth plugin,
// /sid and a /panel page guarded by session.RequireUser("/login"). onLogin nil
// answers "u" for every identity.
func newCallbackApp(t *testing.T, errorPath string, onLogin LoginFunc) *callbackApp {
	t.Helper()
	return newCallbackAppWith(t, errorPath, onLogin, nil)
}

// newCallbackAppWith is newCallbackApp with tune adjusting the Options first.
func newCallbackAppWith(t *testing.T, errorPath string, onLogin LoginFunc, tune func(*Options)) *callbackApp {
	t.Helper()
	a := &callbackApp{f: newFakeProvider(t)}
	if onLogin == nil {
		onLogin = func(context.Context, Identity) (string, error) { return "u", nil }
	}
	opts := Options{
		Providers: []Provider{{Name: "test", Issuer: a.f.URL, ClientID: "client", ClientSecret: "secret"}},
		ErrorPath: errorPath,
		OnLogin: func(ctx context.Context, id Identity) (string, error) {
			a.logins = append(a.logins, id)
			return onLogin(ctx, id)
		},
		HTTPClient: a.f.Client,
	}
	if tune != nil {
		tune(&opts)
	}
	a.p = New(opts)
	cfg := &collage.Config{
		DevMode: true,
		Server:  collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{
			"t/private.html": {Data: []byte(`<div>{{slot "content"}}</div>`)},
			"t/panel.html":   {Data: []byte(`panel`)},
		}, Root: "t"},
		Plugins: []collage.Plugin{
			session.New(session.Options{KeyHex: strings.Repeat("ab", 32)}),
			a.p, sidPlugin{},
		},
	}
	app, err := collage.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	private := collage.NewFragment("private", "private.html").WithGuard(session.RequireUser("/login")).Build()
	page := collage.NewPage("panel").
		WithLayouts(private).
		WithContent(collage.NewFragment("panel", "panel.html").Build()).
		WithPath("en", "/panel").
		Build()
	if err := app.RegisterPage(page); err != nil {
		t.Fatal(err)
	}
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	a.h = app.Handler()
	a.c = collagetest.New(t, a.h)
	return a
}

// login starts a sign-in with next=/panel and registers what /authorize would
// have seen with the fake under code. It returns the state.
func (a *callbackApp) login(t *testing.T, code string) string {
	t.Helper()
	res := a.c.Get("/auth/test/login?next=/panel").WantStatus(http.StatusSeeOther)
	u, err := url.Parse(res.Location())
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	a.f.ExpectCode(code, q.Get("nonce"))
	a.f.RememberChallenge(code, q.Get("code_challenge"))
	a.f.ExpectRedirectURI(code, q.Get("redirect_uri"))
	return q.Get("state")
}

func (a *callbackApp) callback(code, state string) *collagetest.Response {
	return a.c.Get("/auth/test/callback?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state))
}

func (a *callbackApp) sid(t *testing.T) string {
	t.Helper()
	return a.c.Get("/sid").WantStatus(http.StatusOK).Body
}

func (a *callbackApp) wantSignedIn(t *testing.T) {
	t.Helper()
	a.c.Get("/panel").WantStatus(http.StatusOK)
}

func (a *callbackApp) wantSignedOut(t *testing.T) {
	t.Helper()
	res := a.c.Get("/panel").WantStatus(http.StatusSeeOther)
	if !strings.HasPrefix(res.Location(), "/login?") {
		t.Errorf("guarded page sent to %q, want /login", res.Location())
	}
}

// statusFor is the built-in status of each failure code.
var statusFor = map[string]int{
	"state": 400, "expired": 400, "denied": 400, "rejected": 400,
	"exchange": 502, "token": 502,
}

// wantFailure runs scenario twice, on a fresh app with ErrorPath "/oops" and on
// one without, and checks the answer for code and that no one is signed in.
// scenario returns the callback's response.
func wantFailure(t *testing.T, code string, onLogin LoginFunc, scenario func(t *testing.T, a *callbackApp) *collagetest.Response) {
	t.Helper()
	for _, errorPath := range []string{"/oops", ""} {
		t.Run("errorPath="+errorPath, func(t *testing.T) {
			a := newCallbackApp(t, errorPath, onLogin)
			res := scenario(t, a)
			if errorPath != "" {
				res.WantStatus(http.StatusSeeOther)
				if got, want := res.Location(), "/oops?error="+code; got != want {
					t.Errorf("Location = %q, want %q", got, want)
				}
			} else {
				res.WantStatus(statusFor[code])
			}
			a.wantSignedOut(t)
		})
	}
}

func TestCallback_SignsIn(t *testing.T) {
	a := newCallbackApp(t, "", nil)
	a.wantSignedOut(t)
	state := a.login(t, "c1")
	res := a.callback("c1", state).WantStatus(http.StatusSeeOther)
	if got := res.Location(); got != "/panel" {
		t.Errorf("Location = %q, want /panel", got)
	}
	a.wantSignedIn(t)
	want := Identity{Provider: "test", Subject: "u-1", Email: "a@b.c", EmailVerified: true, Name: "A"}
	if len(a.logins) != 1 || a.logins[0] != want {
		t.Errorf("OnLogin got %+v, want [%+v]", a.logins, want)
	}
	if _, ok := a.p.pendingFor(httptest.NewRequest(http.MethodGet, "/", nil), "test"); ok {
		t.Error("pendingFor without a session found a sign-in")
	}
}

// Review Focus 1: a session ID planted before sign-in is not the signed-in one.
func TestCallback_RegeneratesTheSession(t *testing.T) {
	a := newCallbackApp(t, "", nil)
	state := a.login(t, "c1")
	before := a.sid(t)
	if before == "" {
		t.Fatal("the login started no session")
	}
	a.callback("c1", state).WantStatus(http.StatusSeeOther)
	a.wantSignedIn(t)
	if after := a.sid(t); after == before || after == "" {
		t.Errorf("session ID %q before sign-in, %q after", before, after)
	}
}

// Review Focus 2: two tabs signing in; the first callback fails state.
func TestCallback_SecondLoginReplacesTheFirst(t *testing.T) {
	wantFailure(t, "state", nil, func(t *testing.T, a *callbackApp) *collagetest.Response {
		first := a.login(t, "c1")
		a.login(t, "c2")
		return a.callback("c1", first)
	})
}

// Review Focus 3: no session cookie at all.
func TestCallback_NoPendingSignIn(t *testing.T) {
	wantFailure(t, "state", nil, func(t *testing.T, a *callbackApp) *collagetest.Response {
		return a.callback("c1", "anything")
	})
	wantFailure(t, "state", nil, func(t *testing.T, a *callbackApp) *collagetest.Response {
		return a.c.Get("/auth/test/callback")
	})
}

func TestCallback_StateMismatch(t *testing.T) {
	wantFailure(t, "state", nil, func(t *testing.T, a *callbackApp) *collagetest.Response {
		state := a.login(t, "c1")
		return a.callback("c1", state+"x")
	})
	wantFailure(t, "state", nil, func(t *testing.T, a *callbackApp) *collagetest.Response {
		a.login(t, "c1")
		return a.c.Get("/auth/test/callback?code=c1")
	})
}

// The same callback URL twice: the second fails state. The reader stays signed in
// from the first, so the check is on the answer and on the session not changing.
func TestCallback_ReplayFails(t *testing.T) {
	for _, errorPath := range []string{"/oops", ""} {
		t.Run("errorPath="+errorPath, func(t *testing.T) {
			a := newCallbackApp(t, errorPath, nil)
			state := a.login(t, "c1")
			a.callback("c1", state).WantStatus(http.StatusSeeOther)
			sid := a.sid(t)
			res := a.callback("c1", state)
			if errorPath != "" {
				res.WantStatus(http.StatusSeeOther)
				if got := res.Location(); got != "/oops?error=state" {
					t.Errorf("Location = %q", got)
				}
			} else {
				res.WantStatus(http.StatusBadRequest)
			}
			if len(a.logins) != 1 || a.f.TokenCalls.Load() != 1 {
				t.Errorf("OnLogin %d times, /token %d times; want 1 and 1", len(a.logins), a.f.TokenCalls.Load())
			}
			if a.sid(t) != sid {
				t.Error("the replay changed the session")
			}
		})
	}
	// Replayed from another browser, which never started the sign-in.
	wantFailure(t, "state", nil, func(t *testing.T, a *callbackApp) *collagetest.Response {
		state := a.login(t, "c1")
		a.c = collagetest.New(t, a.h)
		return a.callback("c1", state)
	})
}

func TestCallback_Expired(t *testing.T) {
	wantFailure(t, "expired", nil, func(t *testing.T, a *callbackApp) *collagetest.Response {
		state := a.login(t, "c1")
		a.p.now = func() time.Time { return time.Now().Add(10*time.Minute + time.Second) }
		return a.callback("c1", state)
	})
}

func TestCallback_NotYetExpired(t *testing.T) {
	a := newCallbackApp(t, "", nil)
	a.f.IDTokenNumbers = map[string]int64{"exp": time.Now().Add(15 * time.Minute).Unix()}
	state := a.login(t, "c1")
	a.p.now = func() time.Time { return time.Now().Add(9 * time.Minute) }
	a.callback("c1", state).WantStatus(http.StatusSeeOther)
	a.wantSignedIn(t)
}

func TestCallback_Denied(t *testing.T) {
	wantFailure(t, "denied", nil, func(t *testing.T, a *callbackApp) *collagetest.Response {
		state := a.login(t, "c1")
		return a.c.Get("/auth/test/callback?error=access_denied&state=" + url.QueryEscape(state))
	})
}

func TestCallback_ClaimChecks(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		strs map[string]string
		nums map[string]int64
	}{
		{"iss other", map[string]string{"iss": "https://other"}, nil},
		{"aud other", map[string]string{"aud": "other"}, nil},
		{"aud array without client", map[string]string{"aud": `["a","b"]`}, nil},
		{"aud array with client and no azp", map[string]string{"aud": `["client","b"]`}, nil},
		{"aud array with client and azp b", map[string]string{"aud": `["client","b"]`, "azp": "b"}, nil},
		{"azp other with one aud", map[string]string{"azp": "b"}, nil},
		{"exp in the past", nil, map[string]int64{"exp": now.Add(-2 * time.Minute).Unix()}},
		{"exp missing", nil, map[string]int64{"exp": 0}},
		{"iat in the future", nil, map[string]int64{"iat": now.Add(5 * time.Minute).Unix()}},
		{"wrong nonce", map[string]string{"nonce": "other"}, nil},
		{"empty sub", map[string]string{"sub": ""}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantFailure(t, "token", nil, func(t *testing.T, a *callbackApp) *collagetest.Response {
				a.f.IDTokenClaims = tc.strs
				a.f.IDTokenNumbers = tc.nums
				state := a.login(t, "c1")
				return a.callback("c1", state)
			})
		})
	}
	t.Run("aud array with client and azp client passes", func(t *testing.T) {
		a := newCallbackApp(t, "", nil)
		a.f.IDTokenClaims = map[string]string{"aud": `["client","b"]`, "azp": "client"}
		state := a.login(t, "c1")
		res := a.callback("c1", state).WantStatus(http.StatusSeeOther)
		if res.Location() != "/panel" {
			t.Errorf("Location = %q", res.Location())
		}
		a.wantSignedIn(t)
	})
	t.Run("skew within 60s passes", func(t *testing.T) {
		a := newCallbackApp(t, "", nil)
		a.f.IDTokenNumbers = map[string]int64{"exp": now.Add(-30 * time.Second).Unix(), "iat": now.Add(30 * time.Second).Unix()}
		state := a.login(t, "c1")
		a.callback("c1", state).WantStatus(http.StatusSeeOther)
		a.wantSignedIn(t)
	})
	t.Run("email_verified as a string", func(t *testing.T) {
		for raw, want := range map[string]bool{`"true"`: true, `"false"`: false, `false`: false} {
			a := newCallbackApp(t, "", nil)
			a.f.IDTokenClaims = map[string]string{"email_verified": raw}
			state := a.login(t, "c1")
			a.callback("c1", state).WantStatus(http.StatusSeeOther)
			if len(a.logins) != 1 || a.logins[0].EmailVerified != want {
				t.Errorf("email_verified %s gave %+v", raw, a.logins)
			}
		}
	})
}

func TestCallback_TokenEndpointFails(t *testing.T) {
	wantFailure(t, "exchange", nil, func(t *testing.T, a *callbackApp) *collagetest.Response {
		a.f.TokenStatus = http.StatusInternalServerError
		state := a.login(t, "c1")
		return a.callback("c1", state)
	})
	// A code the provider does not know (the fake answers 400).
	wantFailure(t, "exchange", nil, func(t *testing.T, a *callbackApp) *collagetest.Response {
		state := a.login(t, "c1")
		return a.callback("c2", state)
	})
}

func TestCallback_UserinfoFillsTheEmail(t *testing.T) {
	a := newCallbackApp(t, "", nil)
	a.f.IDTokenClaims = map[string]string{"email": "", "email_verified": "false"}
	state := a.login(t, "c1")
	a.callback("c1", state).WantStatus(http.StatusSeeOther)
	if len(a.logins) != 1 || a.logins[0].Email != "a@b.c" || !a.logins[0].EmailVerified {
		t.Errorf("OnLogin got %+v", a.logins)
	}
}

func TestCallback_UserinfoMismatch(t *testing.T) {
	wantFailure(t, "token", nil, func(t *testing.T, a *callbackApp) *collagetest.Response {
		a.f.IDTokenClaims = map[string]string{"email": ""}
		a.f.UserinfoSub = "other"
		state := a.login(t, "c1")
		return a.callback("c1", state)
	})
}

func TestCallback_OnLoginRejects(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		wantFailure(t, "rejected", func(context.Context, Identity) (string, error) {
			return "", errors.New("no")
		}, func(t *testing.T, a *callbackApp) *collagetest.Response {
			return a.callback("c1", a.login(t, "c1"))
		})
	})
	t.Run("empty userID", func(t *testing.T) {
		wantFailure(t, "rejected", func(context.Context, Identity) (string, error) {
			return "", nil
		}, func(t *testing.T, a *callbackApp) *collagetest.Response {
			return a.callback("c1", a.login(t, "c1"))
		})
	})
}

// The fake accepts Basic only, so the client_secret_post branch is checked here.
func TestExchange_ClientAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name    string
		methods []string
		basic   bool
	}{
		{"nothing listed", nil, true},
		{"basic listed", []string{"client_secret_post", "client_secret_basic"}, true},
		{"post only", []string{"client_secret_post"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got *http.Request
			var form url.Values
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				got, form = r, r.PostForm
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"access_token":"at","token_type":"Bearer","expires_in":60,"id_token":"x"}`)
			}))
			defer srv.Close()
			p := New(Options{HTTPClient: srv.Client()})
			pr := &provider{cfg: Provider{Name: "t", ClientID: "cli ent"}, secret: "s:e&c"}
			tok, err := p.exchange(context.Background(), pr, &metadata{TokenEndpoint: srv.URL, TokenAuthMethods: tc.methods}, "the-code", "the-verifier", "https://x/cb")
			if err != nil {
				t.Fatal(err)
			}
			if tok.AccessToken != "at" || tok.ExpiresIn != 60 || tok.IDToken != "x" {
				t.Errorf("token = %+v", tok)
			}
			want := url.Values{"grant_type": {"authorization_code"}, "code": {"the-code"}, "redirect_uri": {"https://x/cb"}, "code_verifier": {"the-verifier"}}
			id, secret, ok := got.BasicAuth()
			if tc.basic {
				if !ok || id != url.QueryEscape("cli ent") || secret != url.QueryEscape("s:e&c") {
					t.Errorf("Basic = %q %q %v", id, secret, ok)
				}
			} else {
				if ok {
					t.Error("Basic sent for client_secret_post")
				}
				want.Set("client_id", "cli ent")
				want.Set("client_secret", "s:e&c")
			}
			if form.Encode() != want.Encode() {
				t.Errorf("form = %s, want %s", form.Encode(), want.Encode())
			}
		})
	}
}

func TestExchange_LimitsAndStatus(t *testing.T) {
	big := strings.Repeat(" ", 1<<20) + `{"access_token":"at"}`
	for name, h := range map[string]http.HandlerFunc{
		"status 400": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, `{"error":"invalid_grant"}`, 400) },
		"over 1 MiB": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, big) },
		"not JSON":   func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "<html>") },
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			p := New(Options{HTTPClient: srv.Client()})
			pr := &provider{cfg: Provider{Name: "t", ClientID: "c"}, secret: "s"}
			if _, err := p.exchange(context.Background(), pr, &metadata{TokenEndpoint: srv.URL}, "c", "v", "r"); err == nil {
				t.Error("no error")
			}
		})
	}
}

func TestClaims_Decode(t *testing.T) {
	cases := map[string]struct {
		json string
		want audience
		ev   bool
	}{
		"aud string":      {`{"aud":"a","email_verified":true}`, audience{"a"}, true},
		"aud array":       {`{"aud":["a","b"],"email_verified":"true"}`, audience{"a", "b"}, true},
		"verified false":  {`{"aud":"a","email_verified":"false"}`, audience{"a"}, false},
		"verified absent": {`{"aud":"a"}`, audience{"a"}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := parseIDToken("e30." + b64(tc.json) + ".")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(c.Aud, ",") != strings.Join(tc.want, ",") || c.EmailVerified != tc.ev {
				t.Errorf("claims = %+v", c)
			}
		})
	}
	for _, bad := range []string{"", "a.b", "a.!!!.c", "e30." + b64(`{"aud":1}`) + ".", "e30." + b64(`{"email_verified":"yes"}`) + "."} {
		if _, err := parseIDToken(bad); err == nil {
			t.Errorf("parseIDToken(%q) gave no error", bad)
		}
	}
	c, err := parseIDToken("e30." + b64(`{"exp":1700000000.0,"iat":1699999999}`) + ".")
	if err != nil || c.Exp != 1700000000 || c.Iat != 1699999999 {
		t.Errorf("numeric dates: %+v %v", c, err)
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// Ruling 5: a sign-in over another user's session starts clean; the same user
// signing in again keeps the session's data.
func TestCallback_SignInOverAnotherUser(t *testing.T) {
	for _, tc := range []struct {
		name, second string
		keep         bool
	}{
		{"another user", "user-2", false},
		{"the same user", "user-1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			userID := "user-1"
			a := newCallbackApp(t, "", func(context.Context, Identity) (string, error) { return userID, nil })
			a.callback("c1", a.login(t, "c1")).WantStatus(http.StatusSeeOther)
			if got := a.c.Get("/kv?k=" + session.UserKey).Body; got != "user-1" {
				t.Fatalf("first sign-in: user %q", got)
			}
			a.c.Get("/kv?k=cart&v=3").WantStatus(http.StatusOK)
			sid := a.sid(t)

			userID = tc.second
			a.callback("c2", a.login(t, "c2")).WantStatus(http.StatusSeeOther)
			if got := a.c.Get("/kv?k=" + session.UserKey).Body; got != tc.second {
				t.Errorf("user = %q, want %q", got, tc.second)
			}
			cart := a.c.Get("/kv?k=cart").Body
			if tc.keep && cart != "3" {
				t.Errorf("the same user's cart = %q, want it kept", cart)
			}
			if !tc.keep && cart != "" {
				t.Errorf("user-2 inherited user-1's cart %q", cart)
			}
			if after := a.sid(t); after == sid || after == "" {
				t.Errorf("session ID %q before, %q after", sid, after)
			}
			a.wantSignedIn(t)
		})
	}
}
