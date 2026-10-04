package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
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
		entered, release := make(chan struct{}), make(chan struct{})
		a.f.Refresh = func(string) (string, string, int) {
			close(entered)
			<-release
			return "new-a", "new-r", 200
		}
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
			marked := a.p.tok.revoking[key] > 0
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
		close(release)

		if err := <-clientErr; !errors.Is(err, ErrNotLinked) {
			t.Errorf("the in-flight Client = %v, want ErrNotLinked", err)
		}
		if err := <-revokeErr; err != nil {
			t.Errorf("Revoke = %v", err)
		}
		if st.row("app-user", "test") != nil {
			t.Error("the in-flight refresh wrote the row back")
		}
		if got := a.f.Revoked(); !slices.Equal(got, []string{"new-r"}) {
			t.Errorf("revoked %v, want the rotated refresh token", got)
		}
		wantNotLinked(t, a, "app-user")
		a.p.tok.mu.Lock()
		defer a.p.tok.mu.Unlock()
		if len(a.p.tok.entries) != 0 || len(a.p.tok.calls) != 0 || len(a.p.tok.revoking) != 0 {
			t.Errorf("state left behind: %d cached, %d calls, %d revoking",
				len(a.p.tok.entries), len(a.p.tok.calls), len(a.p.tok.revoking))
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
