package domain

import "time"

// Endpoint is a discovered, addressable request target (URL + method) within a
// scan. Endpoints accumulate continuously as discovery runs in parallel with
// testing.
type Endpoint struct {
	ID          ID              `json:"id"`
	ScanID      ID              `json:"scan_id"`
	URL         string          `json:"url"`
	Method      HTTPMethod      `json:"method"`
	Source      DiscoverySource `json:"source"`
	ContentType string          `json:"content_type,omitempty"`
	// Fingerprint is a stable hash used to de-duplicate endpoints (set by the
	// discovery layer in later phases; empty in Phase 0).
	Fingerprint string    `json:"fingerprint,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Parameter is an input associated with an endpoint, qualified by its location
// (query/form/json/…). Parameters are the raw material from which injection
// points are derived.
type Parameter struct {
	ID         ID              `json:"id"`
	ScanID     ID              `json:"scan_id"`
	EndpointID ID              `json:"endpoint_id"`
	Name       string          `json:"name"`
	Location   ParamLocation   `json:"location"`
	Example    string          `json:"example,omitempty"` // a sample/observed value
	Source     DiscoverySource `json:"source"`
	CreatedAt  time.Time       `json:"created_at"`
}

// InjectionPoint is the unit of testing: a specific (endpoint, parameter)
// coupling that an engine may exercise. It is generic across vulnerability
// classes — the same injection point can be tested by multiple engines.
//
// Newly created injection points immediately produce test jobs; discovery does
// not block testing.
type InjectionPoint struct {
	ID          ID            `json:"id"`
	ScanID      ID            `json:"scan_id"`
	EndpointID  ID            `json:"endpoint_id"`
	ParameterID ID            `json:"parameter_id"`
	Location    ParamLocation `json:"location"`
	CreatedAt   time.Time     `json:"created_at"`
}
