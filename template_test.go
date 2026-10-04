package oauth

import (
	"context"
	"html"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	session "github.com/Elagoht/collage-session"
	"github.com/Elagoht/collage/pkg/collage"
	"github.com/Elagoht/collage/pkg/collagetest"
)

// siteApp is a development app with session, the oauth plugin (a stub store
// sealed under testKey(7), OnLogin answering "app-user"), one page "/blog"
// rendering tmpl, a guarded "/panel" and a logout action at "/logout".
type siteApp struct {
	c  *collagetest.Client
	p  *Plugin
	f  *fakeProvider
	st *stubStore
}

func newSiteApp(t *testing.T, tmpl string, tune func(*Options)) *siteApp {
	t.Helper()
	s := &siteApp{f: newFakeProvider(t), st: newStubStore()}
	opts := Options{
		Providers:  []Provider{{Name: "test", Issuer: s.f.URL, ClientID: "client", ClientSecret: "secret"}},
		OnLogin:    func(context.Context, Identity) (string, error) { return "app-user", nil },
		HTTPClient: s.f.Client,
		Store:      s.st,
		Key:        testKey(7),
	}
	if tune != nil {
		tune(&opts)
	}
	s.p = New(opts)
	app, err := collage.New(&collage.Config{
		DevMode: true,
		Logger:  slog.New(slog.DiscardHandler),
		Server:  collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{
			"t/private.html": {Data: []byte(`<div>{{slot "content"}}</div>`)},
			"t/panel.html":   {Data: []byte(`panel`)},
			"t/blog.html":    {Data: []byte(tmpl)},
		}, Root: "t"},
		Plugins: []collage.Plugin{session.New(session.Options{KeyHex: strings.Repeat("ab", 32)}), s.p},
	})
	if err != nil {
		t.Fatal(err)
	}
	private := collage.NewFragment("private", "private.html").WithGuard(session.RequireUser("/login")).Build()
	register := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	register(app.RegisterPage(collage.NewPage("panel").WithLayouts(private).
		WithContent(collage.NewFragment("panel", "panel.html").Build()).WithPath("en", "/panel").Build()))
	register(app.RegisterPage(collage.NewPage("blog").
		WithContent(collage.NewFragment("blog", "blog.html").Build()).WithPath("en", "/blog").Build()))
	// The application's logout: nothing of oauth's.
	register(app.RegisterAction(collage.NewAction("logout").WithPath("en", "/logout").WithMethods(http.MethodGet).WithHandler(
		func(_ context.Context, rc *collage.RenderContext) (*collage.ActionResult, error) {
			session.Get(rc).Clear()
			return &collage.ActionResult{Location: "/"}, nil
		}).Build()))
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	s.c = collagetest.New(t, app.Handler())
	return s
}

// href is the first href="..." of body, decoded.
func href(t *testing.T, body string) string {
	t.Helper()
	_, rest, ok := strings.Cut(body, `href="`)
	if !ok {
		t.Fatalf("no href in %q", body)
	}
	v, _, _ := strings.Cut(rest, `"`)
	return html.UnescapeString(v)
}

func TestOauthLogin_DefaultsNextToTheCurrentPage(t *testing.T) {
	s := newSiteApp(t, `<a href="{{oauthLogin "test"}}">x</a>`, nil)
	res := s.c.Get("/blog?p=2").WantStatus(http.StatusOK)
	if got, want := href(t, res.Body), "/auth/test/login?next=%2Fblog%3Fp%3D2"; got != want {
		t.Errorf("href = %q, want %q", got, want)
	}
}

func TestOauthLogin_NamedNext(t *testing.T) {
	s := newSiteApp(t, `<a href="{{oauthLogin "test" "/after"}}">x</a>`, nil)
	res := s.c.Get("/blog?p=2").WantStatus(http.StatusOK)
	if got, want := href(t, res.Body), "/auth/test/login?next=%2Fafter"; got != want {
		t.Errorf("href = %q, want %q", got, want)
	}
}

func TestOauthLogin_FollowsThePrefix(t *testing.T) {
	s := newSiteApp(t, `<a href="{{oauthLogin "test"}}">x</a>`, func(o *Options) { o.Prefix = "/sign/" })
	res := s.c.Get("/blog").WantStatus(http.StatusOK)
	if got, want := href(t, res.Body), "/sign/test/login?next=%2Fblog"; got != want {
		t.Errorf("href = %q, want %q", got, want)
	}
}

func TestOauthLogin_UnknownProviderFailsTheRender(t *testing.T) {
	s := newSiteApp(t, `<a href="{{oauthLogin "nope"}}">x</a>`, nil)
	// A fragment that fails to render is reported, not shown (the development
	// server says why in a comment and an overlay).
	res := s.c.Get("/blog")
	if !strings.Contains(res.Body, `unknown provider &#34;nope&#34;`) {
		t.Errorf("the render did not fail with the provider's name; body:\n%.400s", res.Body)
	}
	if strings.Contains(res.Body, "<a href") {
		t.Errorf("a failed render still produced a link: %.200s", res.Body)
	}
}
