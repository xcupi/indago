package httpengine

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
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
		spec, err := randomizedClientHelloSpec()
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

// The failure was probabilistic (about one handshake in eight), so a single
// real handshake proves little. Repeat enough that a regression cannot hide.
//
// The assertion is precise about the bug fixed here: no handshake may fail with
// the hybrid-group retry error. A randomized hello is also rejected by a server
// very rarely for unrelated reasons (observed about once in 16,000 handshakes,
// as "remote error: tls: handshake failure", root cause not established), so a
// handful of other rejections is tolerated and logged rather than failing the
// suite. Before the fix 57 of 400 handshakes failed, all with the retry error.
func TestRandomizedTLSDialerHandshakeNeverFailsAgainstHybridPreferringServer(t *testing.T) {
	const attempts, otherTolerance = 400, 4
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	dial := randomizedTLSDialer(&net.Dialer{Timeout: 5 * time.Second}, true)
	var retryErrs, otherErrs int
	var firstRetry, firstOther error
	for i := 0; i < attempts; i++ {
		conn, err := dial(context.Background(), "tcp", srv.Listener.Addr().String())
		switch {
		case err == nil:
			conn.Close()
		case strings.Contains(err.Error(), "CurvePreferences includes unsupported curve"):
			retryErrs++
			if firstRetry == nil {
				firstRetry = err
			}
		default:
			otherErrs++
			if firstOther == nil {
				firstOther = err
			}
		}
	}
	if retryErrs > 0 {
		t.Fatalf("%d of %d randomized handshakes failed with the hybrid-group retry error; first: %v", retryErrs, attempts, firstRetry)
	}
	if otherErrs > 0 {
		t.Logf("%d of %d handshakes rejected for another reason (tolerated up to %d); first: %v", otherErrs, attempts, otherTolerance, firstOther)
	}
	if otherErrs > otherTolerance {
		t.Fatalf("%d of %d randomized handshakes failed (more than the %d tolerated); first: %v", otherErrs, attempts, otherTolerance, firstOther)
	}
}
