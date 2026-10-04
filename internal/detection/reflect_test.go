package detection_test

import (
	"encoding/json"
	"html"
	"net/url"
	"strings"
	"testing"

	"github.com/indago/indago/internal/detection"
	"github.com/indago/indago/internal/domain"
)

func TestNewProbeDeterministicAndUnique(t *testing.T) {
	scan := domain.NewID()
	ipA, ipB := domain.NewID(), domain.NewID()

	a1 := detection.NewProbe(scan, ipA)
	a2 := detection.NewProbe(scan, ipA)
	b := detection.NewProbe(scan, ipB)

	if a1 != a2 {
		t.Fatalf("probe must be deterministic: %+v vs %+v", a1, a2)
	}
	if a1.Token == b.Token || a1.Tail == b.Tail {
		t.Fatal("different injection points must get different sentinels")
	}
	if a1.Token == a1.Tail {
		t.Fatal("token and tail must differ")
	}
	v := a1.Value()
	if !strings.HasPrefix(v, a1.Token) || !strings.HasSuffix(v, a1.Tail) || !strings.Contains(v, a1.Canary) {
		t.Fatalf("value layout wrong: %q", v)
	}
	// Sentinels must be alphanumeric so encoders cannot mangle them.
	for _, s := range []string{a1.Token, a1.Tail} {
		for _, r := range s {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
				t.Fatalf("sentinel %q not alphanumeric", s)
			}
		}
	}
}

func TestAnalyzeReflectionRaw(t *testing.T) {
	p := detection.NewProbe(domain.NewID(), domain.NewID())
	body := []byte("<html>hello " + p.Value() + " world</html>")

	rep := detection.AnalyzeReflection(p, []byte("<html>hello world</html>"), body)
	if !rep.Reflected || rep.Count != 1 {
		t.Fatalf("expected one reflection, got reflected=%v count=%d", rep.Reflected, rep.Count)
	}
	if rep.TokenInBaseline {
		t.Fatal("unique token must not appear in baseline")
	}
	loc := rep.Locations[0]
	if loc.Encoding != detection.EncNone {
		t.Fatalf("raw reflection should be encoding=none, got %q (segment %q)", loc.Encoding, loc.Segment)
	}
	if loc.Segment != p.Canary {
		t.Fatalf("segment = %q, want the raw canary %q", loc.Segment, p.Canary)
	}
	if !strings.Contains(loc.Before, "hello ") {
		t.Fatalf("context before not captured: %q", loc.Before)
	}
}

func TestAnalyzeReflectionHTMLEncoded(t *testing.T) {
	p := detection.NewProbe(domain.NewID(), domain.NewID())
	// A target that HTML-encodes the reflected value: token/tail (alphanumeric)
	// survive, the canary comes back as entities.
	body := []byte("<p>" + html.EscapeString(p.Value()) + "</p>")

	rep := detection.AnalyzeReflection(p, nil, body)
	if !rep.Reflected || rep.Count != 1 {
		t.Fatalf("reflected=%v count=%d", rep.Reflected, rep.Count)
	}
	loc := rep.Locations[0]
	if loc.Encoding != detection.EncHTML {
		t.Fatalf("expected html encoding, got %q (segment %q, perchar %v)", loc.Encoding, loc.Segment, loc.PerChar)
	}
	for _, ch := range []string{"<", ">", "\"", "'"} {
		if loc.PerChar[ch] != detection.EncHTML {
			t.Errorf("char %q: form %q, want html", ch, loc.PerChar[ch])
		}
	}
}

func TestAnalyzeReflectionURLEncoded(t *testing.T) {
	p := detection.NewProbe(domain.NewID(), domain.NewID())
	// Reflected into a URL-encoded context: the canary comes back percent-encoded.
	body := []byte(p.Token + url.QueryEscape(p.Canary) + p.Tail)

	rep := detection.AnalyzeReflection(p, nil, body)
	if rep.Count != 1 || rep.Locations[0].Encoding != detection.EncURL {
		t.Fatalf("expected url encoding, got %q (segment %q)", rep.Locations[0].Encoding, rep.Locations[0].Segment)
	}
}

func TestAnalyzeReflectionStripped(t *testing.T) {
	p := detection.NewProbe(domain.NewID(), domain.NewID())
	// The canary is removed but the sentinels remain adjacent.
	body := []byte("x " + p.Token + p.Tail + " y")

	rep := detection.AnalyzeReflection(p, nil, body)
	if rep.Count != 1 {
		t.Fatalf("count = %d", rep.Count)
	}
	if loc := rep.Locations[0]; loc.Encoding != detection.EncStripped || loc.Segment != "" {
		t.Fatalf("expected stripped canary, got encoding=%q segment=%q", loc.Encoding, loc.Segment)
	}
}

func TestAnalyzeReflectionNone(t *testing.T) {
	p := detection.NewProbe(domain.NewID(), domain.NewID())
	rep := detection.AnalyzeReflection(p, []byte("baseline"), []byte("<html>nothing reflected here</html>"))
	if rep.Reflected || rep.Count != 0 || len(rep.Locations) != 0 {
		t.Fatalf("expected no reflection, got %+v", rep)
	}
}

func TestAnalyzeReflectionMultipleLocations(t *testing.T) {
	p := detection.NewProbe(domain.NewID(), domain.NewID())
	v := p.Value()
	body := []byte("<title>" + v + "</title><body>" + v + "</body><!--" + v + "-->")

	rep := detection.AnalyzeReflection(p, nil, body)
	if rep.Count != 3 || len(rep.Locations) != 3 {
		t.Fatalf("expected 3 reflection sites, got count=%d locations=%d", rep.Count, len(rep.Locations))
	}
	if rep.Locations[0].Offset >= rep.Locations[1].Offset {
		t.Fatal("locations should be in body order")
	}
	for _, loc := range rep.Locations {
		if loc.Encoding != detection.EncNone {
			t.Errorf("each raw site should be encoding=none, got %q", loc.Encoding)
		}
	}
}

func TestAnalyzeReflectionTailMissingIsUnknown(t *testing.T) {
	p := detection.NewProbe(domain.NewID(), domain.NewID())
	// Token reflected but the rest of the value truncated away: still reflected,
	// but the transformation cannot be classified.
	body := []byte("prefix " + p.Token + " (cut off)")

	rep := detection.AnalyzeReflection(p, nil, body)
	if rep.Count != 1 || rep.Locations[0].Encoding != detection.EncUnknown {
		t.Fatalf("expected unknown encoding when tail missing, got %q", rep.Locations[0].Encoding)
	}
}

func TestParseReflectionRoundTrip(t *testing.T) {
	if r, err := detection.ParseReflection(nil); r != nil || err != nil {
		t.Fatalf("empty detail should be (nil,nil), got (%v,%v)", r, err)
	}
	p := detection.NewProbe(domain.NewID(), domain.NewID())
	rep := detection.AnalyzeReflection(p, nil, []byte(p.Value()))
	b := mustJSON(t, rep)
	got, err := detection.ParseReflection(b)
	if err != nil || got == nil || !got.Reflected || got.Probe.Token != p.Token {
		t.Fatalf("round-trip failed: %v %+v", err, got)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
