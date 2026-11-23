package scan

import "testing"

func TestWebSocketProtocolSignalReadFromRecordedHandshake(t *testing.T) {
	probe := webSocketProbe{Name: wsProbeCrossOrigin, Status: 101, Switched: true, WebSocket: true}
	if got := webSocketSignals("https://example.test", "/socket", []webSocketProbe{probe}, true, false); len(got) != 0 {
		t.Fatalf("an unvalidated switch produced %d signals", len(got))
	}
	probe.AcceptValid = true
	got := webSocketSignals("https://example.test", "/socket", []webSocketProbe{probe}, true, false)
	if len(got) != 1 || got[0].Kind != wsKindCrossOriginUpgrade {
		t.Fatalf("expected one recorded handshake observation: %+v", got)
	}
}
