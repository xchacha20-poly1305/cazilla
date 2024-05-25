package cazilla

import (
	"crypto/x509"
)

var (
	// CA is a shared CA certificate pool.
	CA = x509.NewCertPool()

	// this loads pre-downloaded CA list from cazilla.
	// note that the CA list may change after a while,
	// so keep a frequent update if you are using this.
	_ = CA.AppendCertsFromPEM(MozillaIncludedCAPEM)
)
