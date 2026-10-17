package httpengine

import (
	"slices"

	utls "github.com/refraction-networking/utls"
)

// randomizedClientHelloSpec returns a freshly randomized ClientHello spec
// (a new PRNG seed on every call), corrected so that it is internally
// consistent. See ensureHybridKeyShare for why the correction is needed.
//
// The spec is applied to a utls.HelloCustom connection with ApplyPreset, which
// fills in the SNI from the connection's config and generates the key shares.
func randomizedClientHelloSpec() (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloRandomized)
	if err != nil {
		return spec, err
	}
	ensureHybridKeyShare(&spec)
	return spec, nil
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
