package oauth

import "net/url"

type presetSpec struct {
	issuer         string
	issuerTemplate string     // an issuer pattern with "{tenantid}", for microsoft "common"
	authParams     url.Values // added to the authorization request when Offline
	offlineScope   bool       // add "offline_access" to the scope when Offline
}

var presets = map[string]presetSpec{
	"google":    {issuer: "https://accounts.google.com", authParams: url.Values{"access_type": {"offline"}, "prompt": {"consent"}}},
	"microsoft": {issuer: "https://login.microsoftonline.com/common/v2.0", issuerTemplate: "https://login.microsoftonline.com/{tenantid}/v2.0", offlineScope: true},
	"gitlab":    {issuer: "https://gitlab.com"},
}
