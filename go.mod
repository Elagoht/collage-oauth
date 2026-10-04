// A collage plugin that signs a reader in with an OpenID Connect provider (Google,
// Microsoft, GitLab or any other) through elagoht/session, and keeps the provider's
// API tokens sealed, refreshed and ready for a client.
//
// It requires collage and collage-session the way any consumer does.
module github.com/Elagoht/collage-oauth

go 1.26

require github.com/Elagoht/collage v0.43.0

require github.com/Elagoht/collage-session v0.2.1
