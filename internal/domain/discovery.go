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
	// RequestBody is a capped copy of the XML request body observed from the
	// browser network. It is deliberately not serialized in API responses;
	// it is used only by the XXE engine after an applicability check.
	RequestBody string `json:"-"`
	// Fingerprint is a stable hash used to de-duplicate endpoints (set by the
	// discovery layer in later phases; empty in Phase 0).
	Fingerprint string    `json:"fingerprint,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Parameter is an input associated with an endpoint, qualified by its location
// (query/form/json/…). Parameters are the raw material from which injection
// points are derived.
type Parameter struct {
	ID         ID            `json:"id"`
	ScanID     ID            `json:"scan_id"`
	EndpointID ID            `json:"endpoint_id"`
	Name       string        `json:"name"`
	Location   ParamLocation `json:"location"`
	Example    string        `json:"example,omitempty"` // sample/observed value; browser-network JSON examples store a serialized JSON literal
	// FormGroup identifies which <form> element this field was discovered in
	// (see discovery.FormGroupKey). One page can hold several forms posting to
	// the SAME action — bWAPP's /commandi.php has three — and their fields are
	// distinct request shapes, not one parameter list: sending a second form's
	// fields (its submit button in particular) makes the target run the wrong
	// handler. A request built for a parameter therefore carries only the
	// parameters of that parameter's form group, plus the empty-group ones
	// (query string, JSON body, header, cookie, path) that belong to the whole
	// endpoint. Empty for every non-form parameter.
	FormGroup string `json:"form_group,omitempty"`
	// Examples holds every DISTINCT value the crawl observed for this
	// parameter, capped (see discovery.MaxObservedExamples). Endpoint dedup
	// collapses /blogs?userId=A and /blogs?userId=B into ONE endpoint, so
	// Example alone keeps only the first value — and an object-identifier
	// differential then has no foreign identifier to try, even though the
	// other users' ids were on the pages the crawl already fetched.
	Examples  []string        `json:"examples,omitempty"`
	Source    DiscoverySource `json:"source"`
	CreatedAt time.Time       `json:"created_at"`
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
