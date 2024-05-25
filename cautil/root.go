package cautil

import (
	"crypto/x509"
	_ "unsafe"

	"github.com/xchacha20-poly1305/cazilla"
)

//go:linkname systemRoots crypto/x509.systemRoots
var systemRoots *x509.CertPool

// UpdateRootCA override the root ca in crypto/x508.systemRoots
func OverrideRootCA() {
	systemRoots = cazilla.CA
}
