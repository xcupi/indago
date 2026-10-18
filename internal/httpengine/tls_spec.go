package httpengine

import (
	"slices"

	utls "github.com/refraction-networking/utls"
)

// randomizedClientHelloSpec returns a randomized ClientHello spec, corrected
// for transport compatibility. Production passes HelloRandomized with no seed,
// so uTLS uses a fresh PRNG seed for each connection; tests can replay an ID
// with a fixed seed without changing global state or production flags.
//
// The spec is applied to a utls.HelloCustom connection with ApplyPreset, which
// fills in the SNI from the connection's config and generates the key shares.
func randomizedClientHelloSpec(id utls.ClientHelloID) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return spec, err
	}
	ensureHybridKeyShare(&spec)
	ensureTLS12AEADCiphers(&spec)
	constrainHTTP1(&spec)
	return spec, nil
}

// ensureTLS12AEADCiphers keeps at least one modern TLS 1.2 ECDHE+AEAD suite
// for each common certificate family. uTLS randomly removes suites without
// preserving certificate compatibility: rarely every usable RSA (or ECDSA)
// suite disappears. A TLS1.2-only hello then fails against an ordinary server
// with that certificate, even though both endpoints support modern ciphers.
// The same floor is needed when a TLS1.3-capable hello meets a TLS1.2 server.
//
// Preserve existing suite order/variety, appending AES-128-GCM only for a
// missing family. Never add legacy RSA key exchange, CBC, SHA-1 or 3DES,
// change protocol versions, or retry a rejected handshake.
func ensureTLS12AEADCiphers(spec *utls.ClientHelloSpec) {
	if spec.TLSVersMin > utls.VersionTLS12 {
		return
	}
	var rsa, ecdsa bool
	for _, cipher := range spec.CipherSuites {
		switch cipher {
		case utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			rsa = true
		case utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
			ecdsa = true
		}
	}
	if !rsa {
		spec.CipherSuites = append(spec.CipherSuites, utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	}
	if !ecdsa {
		spec.CipherSuites = append(spec.CipherSuites, utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	}
}

// constrainHTTP1 aligns the hello with the HTTP/1.x transport that consumes
// UConn. Advertising h2 would let the server select HTTP/2 while net/http
// sends an HTTP/1.1 request: Transport only detects ALPN on a stdlib *tls.Conn,
// not a *utls.UConn. Preserve the random presence/order of other extensions,
// restrict any ALPN to HTTP/1.1, and omit ALPS (HTTP/2 application settings).
// A spec without ALPN stays without ALPN; servers then default to HTTP/1.1.
func constrainHTTP1(spec *utls.ClientHelloSpec) {
	extensions := spec.Extensions[:0]
	for _, extension := range spec.Extensions {
		switch e := extension.(type) {
		case *utls.ALPNExtension:
			e.AlpnProtocols = []string{"http/1.1"}
		case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
			continue
		}
		extensions = append(extensions, extension)
	}
	spec.Extensions = extensions
}

// ensureHybridKeyShare makes a TLS 1.3 spec that lists the X25519MLKEM768
// hybrid group in supported_groups also send a key share for it.
//
// utls's randomizer lists the hybrid group often but only sometimes sends its
// key share. A server that prefers the hybrid group (Go's crypto/tls does)
// then answers with a HelloRetryRequest for it, and utls cannot build a
// hybrid key while handling a retry request, so the handshake fails with
// "tls: CurvePreferences includes unsupported curve" (about one connection in
// eight). No real browser sends that combination: Chrome and Firefox list the
// hybrid group and send its share together. Sending the share also needs no
// retry round trip, which keeps the hello realistic.
//
// The hybrid share goes first and every other share is kept, matching the
// layout the randomizer already produces when it does include the share.
// Specs without a key_share extension (TLS 1.2 only) and specs that do not
// list the hybrid group are left alone. The key material is generated later by
// UConn.ApplyPreset, as for the randomizer's own hybrid shares.
func ensureHybridKeyShare(spec *utls.ClientHelloSpec) {
	var curves *utls.SupportedCurvesExtension
	var shares *utls.KeyShareExtension
	for _, e := range spec.Extensions {
		switch x := e.(type) {
		case *utls.SupportedCurvesExtension:
			curves = x
		case *utls.KeyShareExtension:
			shares = x
		}
	}
	if curves == nil || shares == nil || !slices.Contains(curves.Curves, utls.X25519MLKEM768) {
		return
	}
	for _, k := range shares.KeyShares {
		if k.Group == utls.X25519MLKEM768 {
			return
		}
	}
	shares.KeyShares = append([]utls.KeyShare{{Group: utls.X25519MLKEM768}}, shares.KeyShares...)
}
