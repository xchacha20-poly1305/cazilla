package cautil

import (
	"crypto/tls"
	"net/http"

	"github.com/xchacha20-poly1305/cazilla"
)

// ConfigureHTTPTransport applies cazilla shared CA pool to the given transport. This method is null-safe.
func ConfigureHTTPTransport(t *http.Transport) {
	if t == nil {
		return
	}
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{RootCAs: cazilla.CA}
	} else {
		t.TLSClientConfig.RootCAs = cazilla.CA
	}
}

// ConfigureDefault applies cazilla shared CA pool to http.DefaultTransport,
// which is used by http.DefaultClient.
func ConfigureDefault() {
	ConfigureHTTPTransport(http.DefaultTransport.(*http.Transport))
}
