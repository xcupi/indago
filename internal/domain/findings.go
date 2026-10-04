package domain

import "time"

// Provenance records how and when a finding was discovered and verified, which
// is essential for reproducibility and audit. AIAssisted notes whether an LLM
// advised during triage — but the LLM never decides the verdict.
type Provenance struct {
	Engine          string          `json:"engine"`           // detection engine name
	DiscoverySource DiscoverySource `json:"discovery_source"` // how the endpoint was found
	ToolVersion     string          `json:"tool_version"`
	DetectedAt      time.Time       `json:"detected_at"`
	VerifiedAt      *time.Time      `json:"verified_at,omitempty"`
	AIAssisted      bool            `json:"ai_assisted"` // advisory only; never authoritative
}

// Finding is a candidate or verified vulnerability. A reflection alone yields
// VerdictPending; only browser verification promotes it to Confirmed (or
// demotes to Rejected/Inconclusive). Every Finding links to the Evidence that
// substantiates it.
type Finding struct {
	ID        ID        `json:"id"`
	ScanID    ID        `json:"scan_id"`
	ProjectID ID        `json:"project_id"`
	VulnClass VulnClass `json:"vuln_class"`

	Verdict    Verdict    `json:"verdict"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`

	Title   string `json:"title"`
	Summary string `json:"summary,omitempty"`

	EndpointID       ID            `json:"endpoint_id,omitempty"`
	InjectionPointID ID            `json:"injection_point_id,omitempty"`
	Location         ParamLocation `json:"location,omitempty"`

	EvidenceIDs []ID       `json:"evidence_ids,omitempty"`
	Provenance  Provenance `json:"provenance"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Evidence is a stored artifact backing a finding or test case. Large blobs
// (response bodies, screenshots, HARs) live on the filesystem under the
// evidence root; this record holds the metadata and an integrity hash. The
// BlobPath is relative to the evidence root, never an absolute path.
type Evidence struct {
	ID        ID           `json:"id"`
	ScanID    ID           `json:"scan_id"`
	FindingID ID           `json:"finding_id,omitempty"`
	Kind      EvidenceKind `json:"kind"`
	MediaType string       `json:"media_type,omitempty"`

	BlobPath string `json:"blob_path"` // relative to evidence root
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Note     string `json:"note,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}
