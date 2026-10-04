package oauth

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func sealPlugin(keys ...[]byte) *Plugin { return &Plugin{keys: keys} }

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

var sample = stored{AccessToken: "access-SECRET-1", RefreshToken: "refresh-SECRET-2", Expiry: 1234, Scopes: []string{"openid", "email"}}

func TestSeal_RoundTrip(t *testing.T) {
	p := sealPlugin(testKey(1))
	blob, err := p.seal("u", "google", sample)
	if err != nil {
		t.Fatal(err)
	}
	if blob[0] != 1 {
		t.Errorf("version byte = %d, want 1", blob[0])
	}
	got, current, err := p.open("u", "google", blob)
	if err != nil || !current || !reflect.DeepEqual(got, sample) {
		t.Errorf("open = %+v, %v, %v", got, current, err)
	}
	other, _ := p.seal("u", "google", sample)
	if bytes.Equal(blob, other) {
		t.Error("two seals of one token are identical: the nonce repeats")
	}
}

func TestSeal_HidesTheTokens(t *testing.T) {
	blob, err := sealPlugin(testKey(1)).seal("u", "google", sample)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{sample.AccessToken, sample.RefreshToken, "SECRET"} {
		if bytes.Contains(blob, []byte(s)) {
			t.Errorf("blob contains %q", s)
		}
	}
}

func TestSeal_BoundToUserAndProvider(t *testing.T) {
	p := sealPlugin(testKey(1))
	blob, _ := p.seal("u", "google", sample)
	for _, tc := range [][2]string{{"v", "google"}, {"u", "gitlab"}, {"u", ""}, {"", "google"}} {
		if _, _, err := p.open(tc[0], tc[1], blob); err == nil {
			t.Errorf("opened as (%q, %q)", tc[0], tc[1])
		}
	}
	// The separator keeps ("a","bc") and ("ab","c") apart.
	blob, _ = p.seal("a", "bc", sample)
	if _, _, err := p.open("ab", "c", blob); err == nil {
		t.Error("user/provider boundary is ambiguous")
	}
}

func TestSeal_PreviousKey(t *testing.T) {
	old := sealPlugin(testKey(1))
	blob, _ := old.seal("u", "google", sample)
	rotated := sealPlugin(testKey(2), testKey(1))
	got, current, err := rotated.open("u", "google", blob)
	if err != nil || current || !reflect.DeepEqual(got, sample) {
		t.Errorf("open = %+v, %v, %v; want sample, withCurrent false", got, current, err)
	}
	if _, _, err := sealPlugin(testKey(3)).open("u", "google", blob); err == nil {
		t.Error("an unrelated key opened the blob")
	}
}

func TestSeal_TamperedAndMalformed(t *testing.T) {
	p := sealPlugin(testKey(1))
	blob, _ := p.seal("u", "google", sample)
	for i := range blob {
		bad := bytes.Clone(blob)
		bad[i] ^= 1
		if _, _, err := p.open("u", "google", bad); err == nil {
			t.Fatalf("byte %d flipped and the blob still opened", i)
		}
	}
	for _, v := range []byte{0, 2, 255} {
		bad := bytes.Clone(blob)
		bad[0] = v
		if _, _, err := p.open("u", "google", bad); err == nil {
			t.Errorf("version %d opened", v)
		}
	}
	for _, n := range []int{0, 1, 12, 13, 20} {
		if _, _, err := p.open("u", "google", blob[:min(n, len(blob))]); err == nil {
			t.Errorf("a %d-byte blob opened", n)
		}
	}
	if _, err := sealPlugin().seal("u", "google", sample); err == nil {
		t.Error("sealed without a key")
	}
}

// stubStore is an in-memory TokenStore, safe for concurrent use. Sequential
// tests may read rows directly.
type stubStore struct {
	mu      sync.Mutex
	rows    map[[2]string][]byte
	saveErr error
	deleted int
}

func newStubStore() *stubStore { return &stubStore{rows: map[[2]string][]byte{}} }

func (s *stubStore) Load(_ context.Context, u, p string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.rows[[2]string{u, p}]), nil
}

func (s *stubStore) Save(_ context.Context, u, p string, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	s.rows[[2]string{u, p}] = bytes.Clone(b)
	return nil
}

func (s *stubStore) Delete(_ context.Context, u, p string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted++
	delete(s.rows, [2]string{u, p})
	return nil
}

// deletes counts the calls to Delete.
func (s *stubStore) deletes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleted
}

// row returns the blob for (u, p), nil when there is none.
func (s *stubStore) row(u, p string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.rows[[2]string{u, p}])
}

func TestCallback_SavesSealedTokens(t *testing.T) {
	st := newStubStore()
	a := newCallbackAppWith(t, "", func(context.Context, Identity) (string, error) { return "app-user", nil },
		func(o *Options) { o.Store, o.Key = st, testKey(7) })
	a.callback("c1", a.login(t, "c1")).WantStatus(303)
	a.wantSignedIn(t)
	if len(st.rows) != 1 {
		t.Fatalf("store holds %d rows, want 1", len(st.rows))
	}
	blob := st.rows[[2]string{"app-user", "test"}]
	if len(blob) == 0 {
		t.Fatal("no blob for (app-user, test)")
	}
	if bytes.Contains(blob, []byte("access-c1")) || bytes.Contains(blob, []byte("refresh-c1")) {
		t.Error("the stored blob holds token text")
	}
	got, current, err := a.p.open("app-user", "test", blob)
	if err != nil || !current || got.AccessToken != "access-c1" || got.RefreshToken != "refresh-c1" {
		t.Errorf("open = %+v, %v, %v", got, current, err)
	}
	if want := a.p.clock().Unix() + 3600; got.Expiry < want-5 || got.Expiry > want+5 {
		t.Errorf("Expiry = %d, want about %d", got.Expiry, want)
	}
	if !strings.Contains(strings.Join(got.Scopes, " "), "openid") {
		t.Errorf("Scopes = %v", got.Scopes)
	}
}

func TestCallback_SaveFailureStillSignsIn(t *testing.T) {
	st := newStubStore()
	st.saveErr = errors.New("disk full: access-c1 refresh-c1")
	a := newCallbackAppWith(t, "", nil, func(o *Options) { o.Store, o.Key = st, testKey(7) })
	a.callback("c1", a.login(t, "c1")).WantStatus(303)
	a.wantSignedIn(t)
	out := a.logs.String()
	if !strings.Contains(out, "keeping the tokens failed") {
		t.Errorf("the failure was not logged: %s", out)
	}
	for _, secret := range []string{"access-c1", "refresh-c1", "disk full"} {
		if strings.Contains(out, secret) {
			t.Errorf("the log holds %q: %s", secret, out)
		}
	}
}

func TestCallback_NoLifetimeStoresExpiryZero(t *testing.T) {
	st := newStubStore()
	a := newCallbackAppWith(t, "", func(context.Context, Identity) (string, error) { return "app-user", nil },
		func(o *Options) { o.Store, o.Key = st, testKey(7) })
	a.f.NoExpiry = true
	a.callback("c1", a.login(t, "c1")).WantStatus(303)
	got, _, err := a.p.open("app-user", "test", st.rows[[2]string{"app-user", "test"}])
	if err != nil || got.Expiry != 0 || got.AccessToken != "access-c1" {
		t.Errorf("open = %+v, %v; want Expiry 0", got, err)
	}
}

func TestCallback_ReSignInKeepsTheRefreshToken(t *testing.T) {
	st := newStubStore()
	a := newCallbackAppWith(t, "", func(context.Context, Identity) (string, error) { return "app-user", nil },
		func(o *Options) { o.Store, o.Key = st, testKey(7) })
	a.callback("c1", a.login(t, "c1")).WantStatus(303)
	a.f.NoRefreshToken = true
	a.callback("c2", a.login(t, "c2")).WantStatus(303)
	got, _, err := a.p.open("app-user", "test", st.rows[[2]string{"app-user", "test"}])
	if err != nil || got.RefreshToken != "refresh-c1" || got.AccessToken != "access-c2" {
		t.Errorf("open = %+v, %v; want refresh-c1 with access-c2", got, err)
	}
}

func TestCallback_OfflineScopeIsRecorded(t *testing.T) {
	pr := &provider{cfg: Provider{Offline: true}, preset: presetSpec{offlineScope: true}}
	if got := strings.Join(requestedScopes(pr), " "); got != "openid email profile offline_access" {
		t.Errorf("requestedScopes = %q", got)
	}
}

func TestCallback_NoStoreSavesNothing(t *testing.T) {
	a := newCallbackApp(t, "", nil)
	a.callback("c1", a.login(t, "c1")).WantStatus(303)
	a.wantSignedIn(t)
}
