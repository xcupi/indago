package browser

import "testing"

// TestParseKeyChord locks the one-press contract: known modifier names only,
// each at most once, and exactly one printable ASCII key. A malformed chord
// must fail here rather than turning into an odd multi-key sequence in the
// browser.
func TestParseKeyChord(t *testing.T) {
	tests := []struct {
		chord    string
		wantMods int
		wantKey  string
		wantErr  bool
	}{
		{chord: "Alt+Shift+x", wantMods: 1 | 8, wantKey: "x"},
		{chord: "Control+Alt+x", wantMods: 2 | 1, wantKey: "x"},
		{chord: "Shift+Alt+7", wantMods: 8 | 1, wantKey: "7"},
		{chord: "Alt+x", wantMods: 1, wantKey: "x"},
		{chord: "x", wantErr: true},
		{chord: "Alt+Shift+xy", wantErr: true},
		{chord: "Alt+Alt+x", wantErr: true},
		{chord: "Hyper+x", wantErr: true},
		{chord: "Alt+Shift+", wantErr: true},
		{chord: "Alt+Shift+ ", wantErr: true},
		{chord: "Alt+Shift+é", wantErr: true},
		{chord: "", wantErr: true},
	}
	for _, tc := range tests {
		mods, key, err := parseKeyChord(tc.chord)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parseKeyChord(%q) = %d,%q,nil; want an error", tc.chord, mods, key)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseKeyChord(%q): %v", tc.chord, err)
		}
		if mods != tc.wantMods || key != tc.wantKey {
			t.Fatalf("parseKeyChord(%q) = mods %d key %q, want mods %d key %q", tc.chord, mods, key, tc.wantMods, tc.wantKey)
		}
	}
}

// TestKeyCDPFields pins the CDP key identifiers a chord press carries, so a
// page's own keydown listener sees the same key/code a physical keyboard sends.
func TestKeyCDPFields(t *testing.T) {
	if code, vk, text := keyCDPFields("x", false); code != "KeyX" || vk != 'X' || text != "x" {
		t.Fatalf("keyCDPFields(x, no shift) = %q,%d,%q", code, vk, text)
	}
	if code, vk, text := keyCDPFields("x", true); code != "KeyX" || vk != 'X' || text != "X" {
		t.Fatalf("keyCDPFields(x, shift) = %q,%d,%q", code, vk, text)
	}
	if code, vk, text := keyCDPFields("7", false); code != "Digit7" || vk != '7' || text != "7" {
		t.Fatalf("keyCDPFields(7) = %q,%d,%q", code, vk, text)
	}
}
