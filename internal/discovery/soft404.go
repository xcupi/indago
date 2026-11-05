package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/indago/indago/internal/httpengine"
)

// Soft-404 calibration.
//
// Many sites answer EVERY path with 200 (a SPA shell, a marketing fallback, a
// routing rule that renders "not found" with 200) or with a redirect to the
// home page. Probing a wordlist against such a site without calibration
// reports hundreds of "endpoints" that do not exist, which then become
// hundreds of test jobs and findings — the scanner drowns in its own noise.
//
// So before probing, the content source requests a handful of random paths
// that cannot exist under the seed origin and records what the site does with
// each: status, body length, body hash, content type. A probe is only recorded
// as found when it is NOT explainable by that baseline:
//
//   - a non-"exists" status (404/400/5xx) is never an endpoint, calibrated or
//     not;
//   - the same status AND the same body hash as a baseline sample is the
//     wildcard page, so it is not an endpoint;
//   - the same status and a body length within tolerance is treated as the
//     same page (wildcard pages commonly echo the requested path; fixed-length
//     random tokens keep that echo the same size across samples);
//   - anything else — a different status, or a materially different body — is
//     a real difference and is recorded.
//
// The tolerance is deliberately generous (2% of the baseline length, floor 64
// bytes): missing a borderline page is far cheaper than recording a wildcard
// for every word in the list.

// pageSignature is the comparable fingerprint of one response body.
type pageSignature struct {
	Status      int
	Length      int
	Hash        string
	ContentType string
}

func signatureOf(resp *httpengine.Response) pageSignature {
	ct := ""
	if resp != nil && resp.Headers != nil {
		ct = resp.Headers.Get("Content-Type")
	}
	sig := pageSignature{ContentType: ct}
	if resp == nil {
		return sig
	}
	sig.Status = resp.Status
	sig.Length = len(resp.Body)
	sig.Hash = hashBody(resp.Body)
	return sig
}

func hashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// lengthTolerance is how much a body may differ in size and still be
// considered the same page: 2% of the baseline, never less than 64 bytes.
func lengthTolerance(baseLen int) int {
	t := baseLen / 50
	if t < 64 {
		t = 64
	}
	return t
}

// calibration holds the signatures observed for random, non-existent paths on
// one origin. A nil calibration means "no baseline", and callers must not probe:
// without it there is no way to tell a real endpoint from a wildcard.
type calibration struct {
	samples []pageSignature
}

// calibrate requests calibrationProbes random paths under origin and returns
// their signatures. It spends budget like any other request, and returns an
// error when it could not obtain a sample — the caller then skips the origin
// rather than probing blind.
func calibrate(ctx context.Context, engine httpengine.Engine, in Input, budget *reconBudget, origin string) (*calibration, error) {
	var samples []pageSignature
	for i := 0; i < calibrationProbes; i++ {
		if !budget.take() {
			break
		}
		if err := in.wait(ctx); err != nil {
			return nil, err
		}
		raw := origin + "/" + calibrationPath(origin, i)
		resp, err := engine.Do(ctx, httpengine.GET(raw))
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("calibration request %d for %s: %w", i+1, origin, err)
		}
		samples = append(samples, signatureOf(resp))
	}
	if len(samples) == 0 {
		return nil, fmt.Errorf("no calibration sample for %s", origin)
	}
	return &calibration{samples: samples}, nil
}

// calibrationPath builds a deterministic, fixed-length, certainly-absent path
// token. Deterministic (rather than random) so a scan's request sequence is
// reproducible from its evidence; unique per origin and index so the site
// cannot have pre-seeded it.
func calibrationPath(origin string, i int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("indago-soft404|%s|%d", origin, i)))
	return "indago-" + hex.EncodeToString(sum[:5])
}

// explains reports whether resp is indistinguishable from a calibrated wildcard
// sample (same status and the same, or near-same-sized, body).
func (c *calibration) explains(resp *httpengine.Response) bool {
	if c == nil || len(c.samples) == 0 || resp == nil {
		return false
	}
	sig := signatureOf(resp)
	for _, base := range c.samples {
		if base.Status != sig.Status {
			continue
		}
		if base.Hash == sig.Hash {
			return true
		}
		delta := base.Length - sig.Length
		if delta < 0 {
			delta = -delta
		}
		if delta <= lengthTolerance(base.Length) {
			return true
		}
	}
	return false
}

// looksFound applies the calibration: only a response that both "exists"
// (2xx/3xx/401/403) and cannot be explained by the wildcard baseline is an
// endpoint.
func (c *calibration) looksFound(resp *httpengine.Response) bool {
	if resp == nil || !contentExists(resp.Status) {
		return false
	}
	return !c.explains(resp)
}

// sameBody reports whether two responses are byte-identical in status and body.
// Parameter mining uses it as a stability check: a page that changes between
// two identical requests (CSRF token, rotating ad slot, timestamp) is not a
// usable baseline, because every probe would look like a change.
func sameBody(a, b *httpengine.Response) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Status == b.Status && hashBody(a.Body) == hashBody(b.Body)
}
