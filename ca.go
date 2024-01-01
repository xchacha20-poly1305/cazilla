package cazilla

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"

	"github.com/xchacha20-poly1305/cazilla/embed"
)

var (
	// CA is a shared CA certificate pool.
	CA = x509.NewCertPool()
)

func init() {
	CA.AppendCertsFromPEM(embed.MozillaIncludedCAPEM)
}

// ConfigureHTTPTransport applies cazilla shared CA pool to the given transport. This method is null-safe.
func ConfigureHTTPTransport(t *http.Transport) {
	if t == nil {
		return
	}
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{RootCAs: CA}
	} else {
		t.TLSClientConfig.RootCAs = CA
	}
}

// ConfigureDefault applies cazilla shared CA pool to http.DefaultTransport,
// which is used by http.DefaultClient.
func ConfigureDefault() {
	ConfigureHTTPTransport(http.DefaultTransport.(*http.Transport))
}

func ChangeTLSCA(c *tls.Config) {
	if c == nil {
		return
	}

	c.RootCAs = CA
}

// Use origin http transport
func DefaultHTTPTransport(t *http.Transport) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return
	}

	if t == nil {
		return
	}

	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{RootCAs: pool}
		return
	}

	t.TLSClientConfig.RootCAs = pool
}

func ResetHTTPTransport() {
	DefaultHTTPTransport(http.DefaultTransport.(*http.Transport))
}
