package oauth

import "net/http"

// callback is given its body by the callback task; until then the route is not there.
func (p *Plugin) callback(w http.ResponseWriter, r *http.Request, _ string, _ *provider) {
	p.host.ServeStatus(w, r, http.StatusNotFound)
}
