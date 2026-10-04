package domain

import "time"

// AITaskKind is the category of assistance requested from the AI Gateway. Every
// kind is advisory: the LLM may inform these steps but is never the final
// authority for scope, confirmation, evidence, or any security verdict.
type AITaskKind string

const (
	AIPrioritize       AITaskKind = "prioritize"        // rank endpoints/injection points
	AITriage           AITaskKind = "triage"            // suggest likelihood/next steps
	AIInterpretContext AITaskKind = "interpret_context" // explain a reflection context
	AISuggestPayloads  AITaskKind = "suggest_payloads"  // propose candidate payloads
	AIAnalyzeJS        AITaskKind = "analyze_js"        // summarize client-side JS
	AIDraftReport      AITaskKind = "draft_report"      // draft report prose
)

// IsValid reports whether the AI task kind is a known value.
func (k AITaskKind) IsValid() bool {
	switch k {
	case AIPrioritize, AITriage, AIInterpretContext, AISuggestPayloads, AIAnalyzeJS, AIDraftReport:
		return true
	default:
		return false
	}
}

// AITaskState is the lifecycle of an AI task.
type AITaskState string

const (
	AIPending   AITaskState = "pending"
	AIRunning   AITaskState = "running"
	AISucceeded AITaskState = "succeeded"
	AIFailed    AITaskState = "failed"
	AISkipped   AITaskState = "skipped" // AI disabled or not configured
)

// IsValid reports whether the AI task state is a known value.
func (s AITaskState) IsValid() bool {
	switch s {
	case AIPending, AIRunning, AISucceeded, AIFailed, AISkipped:
		return true
	default:
		return false
	}
}

// AITask records an advisory request to the AI Gateway and its result. The
// Advisory field is always true — it exists to make the non-authoritative
// contract explicit and auditable in persisted records.
type AITask struct {
	ID       ID          `json:"id"`
	ScanID   ID          `json:"scan_id,omitempty"`
	Kind     AITaskKind  `json:"kind"`
	State    AITaskState `json:"state"`
	Provider string      `json:"provider,omitempty"`
	Model    string      `json:"model,omitempty"`
	Advisory bool        `json:"advisory"` // invariant: always true

	Request  []byte `json:"request,omitempty"`  // opaque prompt/input
	Response []byte `json:"response,omitempty"` // opaque model output
	Error    string `json:"error,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
