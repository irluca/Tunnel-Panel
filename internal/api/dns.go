package api

import (
	"net/http"

	"github.com/drs/gre-panel/internal/dns"
	"github.com/drs/gre-panel/internal/i18n"
)

// handleDNSCloudflareTest checks the configured Cloudflare token, without
// changing anything. It is the test the settings page runs before the
// operator trusts the failover.
func (s *Server) handleDNSCloudflareTest(w http.ResponseWriter, r *http.Request) {
	token := s.settings.String("dns.cloudflare.api_token")
	if token == "" {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			i18n.T(r.Context(), "Configure the Cloudflare API token first."), "", nil)
		return
	}
	if err := dns.New(token).VerifyToken(r.Context()); err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleDNSCloudflareCheck runs the failover check now and reports what the
// record points at and whether it moved. It is the manual trigger, and the
// same check the background loop runs on its own.
func (s *Server) handleDNSCloudflareCheck(w http.ResponseWriter, r *http.Request) {
	if s.dnsFailover == nil {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
			i18n.T(r.Context(), "DNS failover is not available on this server."), "", nil)
		return
	}
	content, changed, err := s.dnsFailover.Check(r.Context())
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"content": content, "changed": changed})
}

// handleClusterPeers reports the other panel instances in the cluster and
// what each one answered. It polls them live, so the view is current rather
// than a stored snapshot.
func (s *Server) handleClusterPeers(w http.ResponseWriter, r *http.Request) {
	if s.cluster == nil {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
			i18n.T(r.Context(), "The cluster view is not available on this server."), "", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"peers": s.cluster.Check(r.Context())})
}
