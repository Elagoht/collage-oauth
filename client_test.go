package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"
)

// newClientApp is a callback app whose OnLogin answers "app-user", with a
// stub store sealed under testKey(7).
func newClientApp(t *testing.T, tune func(*Options)) (*callbackApp, *stubStore) {
	t.Helper()
	st := newStubStore()
	a := newCallbackAppWith(t, "", func(context.Context, Identity) (string, error) { return "app-user", nil },
		func(o *Options) {
			o.Store, o.Key = st, testKey(7)
			if tune != nil {
				tune(o)
			}
		})
	return a, st
}

// put seals t for (user, "test") with a's plugin and saves it.
func put(t *testing.T, a *callbackApp, st *stubStore, user string, tok stored) {
	t.Helper()
	blob, err := a.p.seal(user, "test", tok)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(context.Background(), user, "test", blob); err != nil {
		t.Fatal(err)
	}
}

// opened opens the stored row of (user, "test"), failing when there is none.
func opened(t *testing.T, a *callbackApp, st *stubStore, user string) stored {
	t.Helper()
	blob := st.row(user, "test")
	if blob == nil {
		t.Fatalf("no row for %s", user)
	}
	got, _, err := a.p.open(user, "test", blob)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// callAPI GETs the fake's /api through c and returns the Authorization it saw.
func callAPI(c *http.Client, base string) (string, error) {
	res, err := c.Get(base + "/api")
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return string(b), err
}

// wantAPI is callAPI through a new Client for (user, "test").
func wantAPI(t *testing.T, a *callbackApp, user, want string) {
	t.Helper()
	c, err := a.p.Client(context.Background(), user, "test")
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	got, err := callAPI(c, a.f.URL)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got != want {
		t.Errorf("Authorization = %q, want %q", got, want)
	}
}

func wantNotLinked(t *testing.T, a *callbackApp, user string) {
	t.Helper()
	if c, err := a.p.Client(context.Background(), user, "test"); !errors.Is(err, ErrNotLinked) || c != nil {
		t.Errorf("Client = %v, %v; want nil, ErrNotLinked", c, err)
	}
}

func (a *callbackApp) inFive() int64 { return a.p.clock().Add(5 * time.Second).Unix() }

func TestClient_UsesTheStoredToken(t *testing.T) {
	a, _ := newClientApp(t, nil)
	a.callback("c1", a.login(t, "c1")).WantStatus(303)
	wantAPI(t, a, "app-user", "Bearer access-c1")
	if n := a.f.RefreshCalls.Load(); n != 0 {
		t.Errorf("RefreshCalls = %d, want 0", n)
	}
}

func TestClient_SignInAgainReplacesTheCachedToken(t *testing.T) {
	a, _ := newClientApp(t, nil)
	a.callback("c1", a.login(t, "c1")).WantStatus(303)
	wantAPI(t, a, "app-user", "Bearer access-c1")
	a.callback("c2", a.login(t, "c2")).WantStatus(303)
	wantAPI(t, a, "app-user", "Bearer access-c2")
}

func TestClient_RefreshesNearExpiry(t *testing.T) {
	a, st := newClientApp(t, nil)
	a.f.Refresh = func(rt string) (string, string, int) {
		switch rt {
		case "old-r":
			return "new-a", "new-r", 200
		case "keep-r":
			return "new-a2", "", 200
		}
		return "", "", 400
	}
	now := a.p.clock().Unix()
	put(t, a, st, "rotating", stored{AccessToken: "old-a", RefreshToken: "old-r", Expiry: now + 30})
	wantAPI(t, a, "rotating", "Bearer new-a")
	got := opened(t, a, st, "rotating")
	if got.AccessToken != "new-a" || got.RefreshToken != "new-r" || got.Expiry < now+3500 {
		t.Errorf("stored = %+v; want new-a, new-r (rotation kept), an hour", got)
	}

	put(t, a, st, "keeping", stored{AccessToken: "old-a", RefreshToken: "keep-r", Expiry: now + 30})
	wantAPI(t, a, "keeping", "Bearer new-a2")
	if got := opened(t, a, st, "keeping"); got.AccessToken != "new-a2" || got.RefreshToken != "keep-r" {
		t.Errorf("stored = %+v; want new-a2 with the old refresh token kept", got)
	}
	if n := a.f.RefreshCalls.Load(); n != 2 {
		t.Errorf("RefreshCalls = %d, want 2", n)
	}
}

func TestClient_FreshOrLifelessTokenIsNotRefreshed(t *testing.T) {
	a, st := newClientApp(t, nil)
	now := a.p.clock().Unix()
	put(t, a, st, "fresh", stored{AccessToken: "fresh-a", RefreshToken: "r", Expiry: now + 120})
	// Ruling 6: Expiry 0 is "the provider gave no lifetime", valid, never refreshed.
	put(t, a, st, "lifeless", stored{AccessToken: "lifeless-a", RefreshToken: "r"})
	put(t, a, st, "lifeless-norefresh", stored{AccessToken: "lifeless-b"})
	for range 2 { // the second round is served from the cache
		wantAPI(t, a, "fresh", "Bearer fresh-a")
		wantAPI(t, a, "lifeless", "Bearer lifeless-a")
		wantAPI(t, a, "lifeless-norefresh", "Bearer lifeless-b")
	}
	if n := a.f.RefreshCalls.Load(); n != 0 {
		t.Errorf("RefreshCalls = %d, want 0", n)
	}
}

func TestClient_CoalescesRefresh(t *testing.T) {
	a, st := newClientApp(t, nil)
	a.f.Refresh = func(string) (string, string, int) {
		time.Sleep(20 * time.Millisecond) // keep the call open while the others arrive
		return "new-a", "new-r", 200
	}
	put(t, a, st, "app-user", stored{AccessToken: "old-a", RefreshToken: "old-r", Expiry: a.p.clock().Unix() - 10})
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			c, err := a.p.Client(context.Background(), "app-user", "test")
			if err != nil {
				errs <- err
				return
			}
			got, err := callAPI(c, a.f.URL)
			if err == nil && got != "Bearer new-a" {
				err = errors.New("Authorization = " + got)
			}
			if err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := a.f.RefreshCalls.Load(); n != 1 {
		t.Errorf("RefreshCalls = %d, want 1", n)
	}
}

func TestClient_InvalidGrant(t *testing.T) {
	a, st := newClientApp(t, nil) // Refresh nil: 400 invalid_grant
	put(t, a, st, "app-user", stored{AccessToken: "old-a", RefreshToken: "old-r", Expiry: a.inFive()})
	wantNotLinked(t, a, "app-user")
	if st.row("app-user", "test") != nil {
		t.Error("the row survived invalid_grant")
	}
	wantNotLinked(t, a, "app-user")
	if n := a.f.RefreshCalls.Load(); n != 1 {
		t.Errorf("RefreshCalls = %d, want 1", n)
	}
}

func TestClient_RefreshOutageKeepsTheRow(t *testing.T) {
	a, st := newClientApp(t, nil)
	a.f.Refresh = func(string) (string, string, int) { return "", "", 500 }
	now := a.p.clock().Unix()
	// Still valid for a few seconds: the old token is used.
	put(t, a, st, "valid", stored{AccessToken: "valid-a", RefreshToken: "r", Expiry: now + 30})
	wantAPI(t, a, "valid", "Bearer valid-a")
	// Expired: an error, but not ErrNotLinked, and the row stays.
	put(t, a, st, "expired", stored{AccessToken: "expired-a", RefreshToken: "r", Expiry: now - 10})
	if _, err := a.p.Client(context.Background(), "expired", "test"); err == nil || errors.Is(err, ErrNotLinked) {
		t.Errorf("Client = %v; want an error other than ErrNotLinked", err)
	}
	for _, u := range []string{"valid", "expired"} {
		if st.row(u, "test") == nil {
			t.Errorf("%s: a 500 deleted the row", u)
		}
	}
}

func TestClient_NoRefreshToken(t *testing.T) {
	a, st := newClientApp(t, nil)
	now := a.p.clock().Unix()
	put(t, a, st, "expired", stored{AccessToken: "a", Expiry: now - 1})
	wantNotLinked(t, a, "expired")
	// Inside the refresh window but not expired, there is nothing to refresh with:
	// the token still works.
	put(t, a, st, "closing", stored{AccessToken: "closing-a", Expiry: now + 30})
	wantAPI(t, a, "closing", "Bearer closing-a")
	if n := a.f.RefreshCalls.Load(); n != 0 {
		t.Errorf("RefreshCalls = %d, want 0", n)
	}
}

func TestClient_NotLinked(t *testing.T) {
	a, _ := newClientApp(t, nil)
	wantNotLinked(t, a, "nobody")
	if _, err := a.p.Client(context.Background(), "app-user", "nope"); !errors.Is(err, ErrNotLinked) {
		t.Errorf("unknown provider: %v, want ErrNotLinked", err)
	}

	noStore := newCallbackApp(t, "", nil)
	wantNotLinked(t, noStore, "u")
	if err := noStore.p.Revoke(context.Background(), "u", "test"); !errors.Is(err, ErrNotLinked) {
		t.Errorf("Revoke without a Store = %v, want ErrNotLinked", err)
	}
}

func TestClient_ReSealsWithCurrentKey(t *testing.T) {
	a, st := newClientApp(t, func(o *Options) { o.PreviousKeys = [][]byte{testKey(1)} })
	a.f.Refresh = func(string) (string, string, int) { return "new-a", "new-r", 200 }
	old, current := sealPlugin(testKey(1)), sealPlugin(testKey(7))
	now := a.p.clock().Unix()
	for _, tc := range []struct {
		user   string
		expiry int64
		want   string
	}{
		{"refreshed", now + 30, "new-a"},
		{"unrefreshed", now + 3600, "old-a"},
	} {
		blob, _ := old.seal(tc.user, "test", stored{AccessToken: "old-a", RefreshToken: "old-r", Expiry: tc.expiry})
		_ = st.Save(context.Background(), tc.user, "test", blob)
		wantAPI(t, a, tc.user, "Bearer "+tc.want)
		got, _, err := current.open(tc.user, "test", st.row(tc.user, "test"))
		if err != nil || got.AccessToken != tc.want {
			t.Errorf("%s: under Key = %+v, %v; want sealed again with Key", tc.user, got, err)
		}
	}
}

func TestRevoke_DropsTheCache(t *testing.T) {
	ctx := context.Background()
	a, st := newClientApp(t, nil)
	a.callback("c1", a.login(t, "c1")).WantStatus(303)
	warm, err := a.p.Client(ctx, "app-user", "test")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := callAPI(warm, a.f.URL); got != "Bearer access-c1" {
		t.Fatalf("warm-up Authorization = %q", got)
	}

	if err := a.p.Revoke(ctx, "app-user", "test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got := a.f.Revoked(); !slices.Equal(got, []string{"refresh-c1"}) {
		t.Errorf("revoked %v, want the refresh token", got)
	}
	if st.row("app-user", "test") != nil {
		t.Error("the row survived Revoke")
	}
	wantNotLinked(t, a, "app-user")
	// A Client made before Revoke does not resurrect the token either.
	if _, err := callAPI(warm, a.f.URL); !errors.Is(err, ErrNotLinked) {
		t.Errorf("the old Client after Revoke: %v, want ErrNotLinked", err)
	}
	if err := a.p.Revoke(ctx, "app-user", "test"); !errors.Is(err, ErrNotLinked) {
		t.Errorf("Revoke again = %v, want ErrNotLinked", err)
	}

	// Without a refresh token, the access token is revoked.
	put(t, a, st, "access-only", stored{AccessToken: "only-a", Expiry: a.p.clock().Unix() + 3600})
	if err := a.p.Revoke(ctx, "access-only", "test"); err != nil {
		t.Fatal(err)
	}
	if got := a.f.Revoked(); !slices.Contains(got, "only-a") {
		t.Errorf("revoked %v, want only-a", got)
	}

	// A refresh in flight when Revoke starts must not put the token back.
	t.Run("an in-flight refresh does not write back", func(t *testing.T) {
		ctx := context.Background()
		a, st := newClientApp(t, nil)
		entered, release := blockRefresh(t, a, 200)
		put(t, a, st, "app-user", stored{AccessToken: "old-a", RefreshToken: "old-r", Expiry: a.p.clock().Unix() - 10})

		clientErr := make(chan error, 1)
		go func() {
			_, err := a.p.Client(ctx, "app-user", "test")
			clientErr <- err
		}()
		<-entered
		revokeErr := make(chan error, 1)
		go func() { revokeErr <- a.p.Revoke(ctx, "app-user", "test") }()
		key := tokenKey{"app-user", "test"}
		for deadline := time.Now().Add(5 * time.Second); ; {
			a.p.tok.mu.Lock()
			marked := a.p.tok.holds[key] != nil && a.p.tok.holds[key].revokes > 0
			a.p.tok.mu.Unlock()
			if marked {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("Revoke never marked the key")
			}
			time.Sleep(time.Millisecond)
		}
		// A Client asked while Revoke runs gets nothing either.
		wantNotLinked(t, a, "app-user")
		release()

		if err := <-clientErr; !errors.Is(err, ErrNotLinked) {
			t.Errorf("the in-flight Client = %v, want ErrNotLinked", err)
		}
		if err := <-revokeErr; err != nil {
			t.Errorf("Revoke = %v", err)
		}
		if st.row("app-user", "test") != nil {
			t.Error("the in-flight refresh wrote the row back")
		}
		if got := a.f.Revoked(); !slices.Equal(got, []string{"refreshed-r"}) {
			t.Errorf("revoked %v, want the rotated refresh token", got)
		}
		wantNotLinked(t, a, "app-user")
		a.p.tok.mu.Lock()
		defer a.p.tok.mu.Unlock()
		if len(a.p.tok.entries) != 0 || len(a.p.tok.calls) != 0 || len(a.p.tok.holds) != 0 {
			t.Errorf("state left behind: %d cached, %d calls, %d holds",
				len(a.p.tok.entries), len(a.p.tok.calls), len(a.p.tok.holds))
		}
	})
}

func TestTokenCache_OldestGoesFirst(t *testing.T) {
	c := &tokenState{max: 2}
	k := func(u string) tokenKey { return tokenKey{u, "p"} }
	c.put(k("a"), stored{AccessToken: "1"})
	c.put(k("b"), stored{AccessToken: "2"})
	c.put(k("a"), stored{AccessToken: "1b"}) // an update keeps its place
	c.put(k("c"), stored{AccessToken: "3"})
	if _, ok := c.get(k("a")); ok {
		t.Error("the oldest entry survived")
	}
	for u, want := range map[string]string{"b": "2", "c": "3"} {
		if got, ok := c.get(k(u)); !ok || got.AccessToken != want {
			t.Errorf("%s = %+v, %v", u, got, ok)
		}
	}
	c.drop(k("b"))
	c.put(k("d"), stored{})
	if len(c.entries) != 2 || c.order.Len() != 2 {
		t.Errorf("%d entries, %d in order; want 2", len(c.entries), c.order.Len())
	}
}

func TestBearer_ClosesTheBodyOnError(t *testing.T) {
	a, _ := newClientApp(t, nil)
	tr := &bearer{p: a.p, userID: "nobody", provider: "test", base: http.DefaultTransport}
	body := &closeSpy{}
	req, _ := http.NewRequest(http.MethodPost, a.f.URL+"/api", body)
	if _, err := tr.RoundTrip(req); !errors.Is(err, ErrNotLinked) {
		t.Errorf("RoundTrip = %v, want ErrNotLinked", err)
	}
	if !body.closed {
		t.Error("the request body was not closed")
	}
}

type closeSpy struct{ closed bool }

func (c *closeSpy) Read([]byte) (int, error) { return 0, io.EOF }
func (c *closeSpy) Close() error             { c.closed = true; return nil }

// waitHold polls until k's hold has at least revokes Revokes and signIns sign-ins.
func waitHold(t *testing.T, p *Plugin, k tokenKey, revokes, signIns int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		p.tok.mu.Lock()
		h := p.tok.holds[k]
		ok := h != nil && h.revokes >= revokes && h.signIns >= signIns
		p.tok.mu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no hold with %d revokes, %d sign-ins on %v", revokes, signIns, k)
		}
		time.Sleep(time.Millisecond)
	}
}

// blockRefresh makes the fake's refresh wait until release is called, answering
// with status; entered is closed when it starts. A failing test releases it at
// cleanup, so it never hangs.
func blockRefresh(t *testing.T, a *callbackApp, status int) (entered chan struct{}, release func()) {
	entered = make(chan struct{})
	gate := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	a.f.Refresh = func(string) (string, string, int) {
		close(entered)
		<-gate
		return "refreshed-a", "refreshed-r", status
	}
	return entered, release
}

// A refresh in flight when the user signs in again must not overwrite the new
// sign-in's row, nor delete it on invalid_grant.
func TestSignIn_SupersedesARefreshInFlight(t *testing.T) {
	for name, status := range map[string]int{"refresh succeeds": 200, "refresh invalid_grant": 400} {
		t.Run(name, func(t *testing.T) {
			a, st := newClientApp(t, nil)
			entered, release := blockRefresh(t, a, status)
			put(t, a, st, "app-user", stored{AccessToken: "old-a", RefreshToken: "old-r", Expiry: a.p.clock().Unix() - 10})

			type result struct {
				auth string
				err  error
			}
			clientRes := make(chan result, 1)
			go func() {
				c, err := a.p.Client(context.Background(), "app-user", "test")
				if err != nil {
					clientRes <- result{err: err}
					return
				}
				got, err := callAPI(c, a.f.URL)
				clientRes <- result{got, err}
			}()
			<-entered
			state := a.login(t, "c2")
			signedIn := make(chan int, 1)
			go func() { signedIn <- a.callback("c2", state).Status }()
			// Release the refresh once the sign-in is saving: it holds the key,
			// or, were it not to wait, it has already finished.
			status := 0
			for deadline := time.Now().Add(5 * time.Second); status == 0; time.Sleep(time.Millisecond) {
				select {
				case status = <-signedIn:
				default:
				}
				a.p.tok.mu.Lock()
				held := a.p.tok.holds[tokenKey{"app-user", "test"}] != nil
				a.p.tok.mu.Unlock()
				if held || time.Now().After(deadline) {
					break
				}
			}
			release()
			if status == 0 {
				status = <-signedIn
			}
			if status != http.StatusSeeOther {
				t.Fatalf("sign-in status %d", status)
			}
			if n := st.deletes(); n != 0 {
				t.Errorf("the superseded refresh deleted the row %d times", n)
			}
			if got := opened(t, a, st, "app-user"); got.AccessToken != "access-c2" || got.RefreshToken != "refresh-c2" {
				t.Errorf("stored = %+v; want the second sign-in's tokens", got)
			}
			// The waiters of the superseded refresh ask again and get the sign-in's token.
			if r := <-clientRes; r.err != nil || r.auth != "Bearer access-c2" {
				t.Errorf("the in-flight Client = %q, %v; want Bearer access-c2", r.auth, r.err)
			}
			wantAPI(t, a, "app-user", "Bearer access-c2")
		})
	}
}

// A second Revoke waits for the refresh in flight just as the first does.
func TestRevoke_TwoRevokesBothWait(t *testing.T) {
	ctx := context.Background()
	a, st := newClientApp(t, nil)
	entered, release := blockRefresh(t, a, 200)
	put(t, a, st, "app-user", stored{AccessToken: "old-a", RefreshToken: "old-r", Expiry: a.p.clock().Unix() - 10})
	go func() { _, _ = a.p.Client(ctx, "app-user", "test") }()
	<-entered
	k := tokenKey{"app-user", "test"}
	errs := make(chan error, 2)
	go func() { errs <- a.p.Revoke(ctx, "app-user", "test") }()
	waitHold(t, a.p, k, 1, 0)
	go func() { errs <- a.p.Revoke(ctx, "app-user", "test") }()
	waitHold(t, a.p, k, 2, 0)
	time.Sleep(20 * time.Millisecond)
	select {
	case err := <-errs:
		t.Fatalf("a Revoke returned (%v) while the refresh was still in flight", err)
	default:
	}
	release()
	// Both may find the row (and both revoke it) or the later one may find none.
	for range 2 {
		if err := <-errs; err != nil && !errors.Is(err, ErrNotLinked) {
			t.Errorf("Revoke = %v", err)
		}
	}
	if st.row("app-user", "test") != nil {
		t.Error("the refresh wrote the row back after the Revokes")
	}
	// Each revoked the rotated token: neither went ahead with the old row.
	got := a.f.Revoked()
	if len(got) == 0 || slices.ContainsFunc(got, func(s string) bool { return s != "refreshed-r" }) {
		t.Errorf("revoked %v, want only the rotated refresh token", got)
	}
}

func TestBearer_TokenStaysWithItsHost(t *testing.T) {
	a, _ := newClientApp(t, nil)
	a.callback("c1", a.login(t, "c1")).WantStatus(303)
	c, err := a.p.Client(context.Background(), "app-user", "test")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seenByOther := "unset"
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seenByOther = r.Header.Get("Authorization")
		mu.Unlock()
	}))
	t.Cleanup(other.Close)
	otherURL, _ := url.Parse(other.URL)
	sawOther := func() string {
		mu.Lock()
		defer mu.Unlock()
		s := seenByOther
		seenByOther = "unset"
		return s
	}

	t.Run("same host keeps it", func(t *testing.T) {
		if got, err := callAPI(c, a.f.URL+"/redirect?to=/api&x="); err != nil || got != "Bearer access-c1" {
			t.Errorf("after a same-host redirect: %q, %v", got, err)
		}
	})
	t.Run("another host gets none", func(t *testing.T) {
		// A loopback http API at 127.0.0.1 redirecting to localhost: the first
		// hop carries the token, the second does not.
		first := make(chan string, 1)
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			first <- r.Header.Get("Authorization")
			http.Redirect(w, r, "http://localhost:"+otherURL.Port()+"/", http.StatusFound)
		}))
		t.Cleanup(api.Close)
		res, err := c.Get(api.URL)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if got := <-first; got != "Bearer access-c1" {
			t.Errorf("the first host got %q", got)
		}
		if got := sawOther(); got != "" {
			t.Errorf("the redirect's host got %q", got)
		}
	})
	t.Run("https to http gets none", func(t *testing.T) {
		// Same hostname (127.0.0.1), downgraded.
		res, err := c.Get(a.f.URL + "/redirect?to=" + url.QueryEscape(other.URL+"/"))
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if got := sawOther(); got != "" {
			t.Errorf("the downgraded hop got %q", got)
		}
	})
	t.Run("plain http elsewhere is refused", func(t *testing.T) {
		if _, err := c.Get("http://example.invalid/api"); !errors.Is(err, errInsecureHost) {
			t.Errorf("Get = %v, want errInsecureHost", err)
		}
	})
}

func TestBearer_HostRules(t *testing.T) {
	for _, tc := range []struct {
		sub, parent string
		want        bool
	}{
		{"api.example.com", "api.example.com", true},
		{"eu.api.example.com", "api.example.com", true},
		{"evilapi.example.com", "api.example.com", false},
		{"example.com", "api.example.com", false},
		{"::1", "::1", true},
		{"a::1", "::1", false},
	} {
		if got := isDomainOrSubdomain(tc.sub, tc.parent); got != tc.want {
			t.Errorf("isDomainOrSubdomain(%q, %q) = %v", tc.sub, tc.parent, got)
		}
	}
	for raw, want := range map[string]bool{
		"https://api.example.com/": true, "HTTPS://x/": true,
		"http://127.0.0.1:8080/": true, "http://[::1]/": true, "http://LOCALHOST/": true, "http://127.0.0.5/": true,
		"http://a.localhost/": false, "http://localhost.example.com/": false,
		"http://api.example.com/": false, "http://10.0.0.1/": false, "ftp://x/": false,
	} {
		u, _ := url.Parse(raw)
		if got := clearTextOK(u); got != want {
			t.Errorf("clearTextOK(%s) = %v", raw, got)
		}
	}
}

// nilRequest is a transport that leaves Response.Request unset, as a mock or a
// recorder may.
type nilRequest struct{ base http.RoundTripper }

func (n nilRequest) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := n.base.RoundTrip(req)
	if res != nil {
		res.Request = nil
	}
	return res, err
}

// recorder answers 200 and keeps the Authorization of each request.
type recorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.seen = append(r.seen, req.Header.Get("Authorization"))
	r.mu.Unlock()
	return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}, Request: req}, nil
}

func TestBearer_FailsClosedWithoutTheChain(t *testing.T) {
	a, _ := newClientApp(t, nil)
	a.callback("c1", a.login(t, "c1")).WantStatus(303)

	t.Run("a transport that leaves Response.Request unset", func(t *testing.T) {
		seen := make(chan string, 1)
		other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			seen <- r.Header.Get("Authorization")
		}))
		t.Cleanup(other.Close)
		otherURL, _ := url.Parse(other.URL)
		c := &http.Client{Transport: &bearer{p: a.p, userID: "app-user", provider: "test", base: nilRequest{a.f.Client.Transport}}}
		res, err := c.Get(a.f.URL + "/redirect?to=" + url.QueryEscape("http://localhost:"+otherURL.Port()+"/"))
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if got := <-seen; got != "" {
			t.Errorf("the other host got %q", got)
		}
		if res.Request == nil {
			t.Error("Response.Request is still unset")
		}
	})
	t.Run("a hop whose chain breaks gets no token", func(t *testing.T) {
		rec := &recorder{}
		b := &bearer{p: a.p, userID: "app-user", provider: "test", base: rec}
		req, _ := http.NewRequest(http.MethodGet, a.f.URL+"/api", nil)
		req.Response = &http.Response{} // a redirect hop with no Request behind it
		res, err := b.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		first, _ := http.NewRequest(http.MethodGet, a.f.URL+"/api", nil)
		res, err = b.RoundTrip(first)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		rec.mu.Lock()
		defer rec.mu.Unlock()
		if !slices.Equal(rec.seen, []string{"", "Bearer access-c1"}) {
			t.Errorf("Authorization sent = %q; want none on the broken hop, the token on a first request", rec.seen)
		}
	})
}

// A sign-in that gives up waiting for a refresh in flight saves; the refresh,
// finishing later, does not save over it.
func TestSignIn_SupersededRefreshFinishingLaterDoesNotSave(t *testing.T) {
	a, st := newClientApp(t, nil)
	a.p.tok.signInWait = 20 * time.Millisecond
	entered, release := blockRefresh(t, a, 200)
	put(t, a, st, "app-user", stored{AccessToken: "old-a", RefreshToken: "old-r", Expiry: a.p.clock().Unix() - 10})
	type result struct {
		auth string
		err  error
	}
	clientRes := make(chan result, 1)
	go func() {
		c, err := a.p.Client(context.Background(), "app-user", "test")
		if err != nil {
			clientRes <- result{err: err}
			return
		}
		got, err := callAPI(c, a.f.URL)
		clientRes <- result{got, err}
	}()
	<-entered
	a.callback("c2", a.login(t, "c2")).WantStatus(303) // waits 20ms, then saves
	release()
	if r := <-clientRes; r.err != nil || r.auth != "Bearer access-c2" {
		t.Errorf("the in-flight Client = %q, %v; want Bearer access-c2", r.auth, r.err)
	}
	if got := opened(t, a, st, "app-user"); got.AccessToken != "access-c2" || got.RefreshToken != "refresh-c2" {
		t.Errorf("stored = %+v; want the sign-in's tokens", got)
	}
}

// A sign-in without a refresh token, over a refresh it superseded, keeps the
// refresh token that refresh rotated to (Ruling 7), though the refresh did not save.
func TestSignIn_KeepsTheSupersededRotation(t *testing.T) {
	a, st := newClientApp(t, nil)
	entered, release := blockRefresh(t, a, 200)
	put(t, a, st, "app-user", stored{AccessToken: "old-a", RefreshToken: "old-r", Expiry: a.p.clock().Unix() - 10})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = a.p.Client(context.Background(), "app-user", "test")
	}()
	<-entered
	a.f.NoRefreshToken = true
	state := a.login(t, "c2")
	signedIn := make(chan int, 1)
	go func() { signedIn <- a.callback("c2", state).Status }()
	waitHold(t, a.p, tokenKey{"app-user", "test"}, 0, 1)
	release()
	if got := <-signedIn; got != http.StatusSeeOther {
		t.Fatalf("sign-in status %d", got)
	}
	<-done
	if got := opened(t, a, st, "app-user"); got.AccessToken != "access-c2" || got.RefreshToken != "refreshed-r" {
		t.Errorf("stored = %+v; want access-c2 with the rotated refreshed-r", got)
	}
}
