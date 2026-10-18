package httpengine

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func specParts(spec *utls.ClientHelloSpec) (curves *utls.SupportedCurvesExtension, shares *utls.KeyShareExtension) {
	for _, e := range spec.Extensions {
		switch x := e.(type) {
		case *utls.SupportedCurvesExtension:
			curves = x
		case *utls.KeyShareExtension:
			shares = x
		}
	}
	return curves, shares
}

func shareGroups(shares *utls.KeyShareExtension) []utls.CurveID {
	var out []utls.CurveID
	for _, k := range shares.KeyShares {
		out = append(out, k.Group)
	}
	return out
}

// A TLS 1.3 server that prefers the hybrid group answers a hello that lists it
// without a key share with a HelloRetryRequest for that group, and utls cannot
// build a hybrid key from an HRR. The listed group must therefore always ship
// with its key share, as real browsers send it.
func TestEnsureHybridKeyShareAddsMissingShare(t *testing.T) {
	spec := &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{
		&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519MLKEM768, utls.X25519, utls.CurveP256}},
		&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
	}}
	ensureHybridKeyShare(spec)
	_, shares := specParts(spec)
	got := shareGroups(shares)
	want := []utls.CurveID{utls.X25519MLKEM768, utls.X25519}
	if !slices.Equal(got, want) {
		t.Fatalf("key share groups = %v, want %v (hybrid first, existing share kept)", got, want)
	}
}

func TestEnsureHybridKeyShareLeavesOtherSpecsAlone(t *testing.T) {
	cases := map[string]*utls.ClientHelloSpec{
		"already has the hybrid share": {Extensions: []utls.TLSExtension{
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519MLKEM768, utls.X25519}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519MLKEM768}, {Group: utls.X25519}}},
		}},
		"hybrid group not listed": {Extensions: []utls.TLSExtension{
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
		}},
	}
	for name, spec := range cases {
		_, shares := specParts(spec)
		before := slices.Clone(shareGroups(shares))
		ensureHybridKeyShare(spec)
		if after := shareGroups(shares); !slices.Equal(before, after) {
			t.Errorf("%s: key share groups changed from %v to %v", name, before, after)
		}
	}
	// A TLS 1.2-only spec has no key_share extension at all: nothing to add.
	spec := &utls.ClientHelloSpec{Extensions: []utls.TLSExtension{
		&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519MLKEM768, utls.X25519}},
	}}
	ensureHybridKeyShare(spec)
	if _, shares := specParts(spec); shares != nil {
		t.Error("a key_share extension was invented for a TLS 1.2-only spec")
	}
}

// Over many random specs, a listed hybrid group always has its key share.
func TestRandomizedClientHelloSpecIsInternallyConsistent(t *testing.T) {
	inconsistent := 0
	for i := 0; i < 1000; i++ {
		spec, err := randomizedClientHelloSpec(utls.HelloRandomized)
		if err != nil {
			t.Fatal(err)
		}
		curves, shares := specParts(&spec)
		if curves == nil || shares == nil {
			continue
		}
		if slices.Contains(curves.Curves, utls.X25519MLKEM768) && !slices.Contains(shareGroups(shares), utls.X25519MLKEM768) {
			inconsistent++
		}
	}
	if inconsistent > 0 {
		t.Fatalf("%d of 1000 randomized specs list X25519MLKEM768 without sending its key share", inconsistent)
	}
}

// A single random handshake can hide rare cipher/curve gaps. Every handshake
// must now succeed: deterministic seed replays cover the former rare cipher
// rejection, so there is no tolerance for "unrelated" handshake failures.
func TestRandomizedTLSDialerHandshakeNeverFailsAgainstHybridPreferringServer(t *testing.T) {
	const attempts = 400
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	dial := randomizedTLSDialer(&net.Dialer{Timeout: 5 * time.Second}, true)
	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := dial(ctx, "tcp", srv.Listener.Addr().String())
		cancel()
		if err != nil {
			t.Fatalf("randomized handshake %d of %d failed (zero tolerance): %v", i+1, attempts, err)
		}
		conn.Close()
	}
}
