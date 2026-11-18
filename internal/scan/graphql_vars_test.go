package scan

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/indago/indago/internal/domain"
)

func TestBuildRequestGraphQLVariables(t *testing.T) {
	ep := &domain.Endpoint{
		ID:          "ep-gql",
		URL:         "http://example.test/graphql",
		Method:      domain.MethodPOST,
		ContentType: "application/json",
	}
	queryParam := &domain.Parameter{
		ID:        "p-query",
		Name:      "query",
		Location:  domain.LocationJSON,
		Example:   "query($id: Int, $title: String) { paste(id: $id, title: $title) { id title } }",
		FormGroup: "gql:query:paste",
		Source:    domain.SourceWellKnown,
	}
	idParam := &domain.Parameter{
		ID:        "p-id",
		Name:      "variables.id",
		Location:  domain.LocationJSON,
		Example:   "1",
		FormGroup: "gql:query:paste",
		Source:    domain.SourceWellKnown,
	}
	titleParam := &domain.Parameter{
		ID:        "p-title",
		Name:      "variables.title",
		Location:  domain.LocationJSON,
		Example:   "indago",
		FormGroup: "gql:query:paste",
		Source:    domain.SourceWellKnown,
	}
	otherGroupParam := &domain.Parameter{
		ID:        "p-other",
		Name:      "variables.cmd",
		Location:  domain.LocationJSON,
		Example:   "indago",
		FormGroup: "gql:query:systemDiagnostics",
		Source:    domain.SourceWellKnown,
	}

	all := []*domain.Parameter{queryParam, idParam, titleParam, otherGroupParam}
	focused := paramsForFocus(all, titleParam)
	req, err := buildRequest(ep, focused, &injection{param: titleParam, value: "injected-title"})
	if err != nil {
		t.Fatalf("buildRequest failed: %v", err)
	}
	if req.Method != http.MethodPost {
		t.Fatalf("expected POST, got %s", req.Method)
	}
	if !strings.Contains(req.ContentType, "application/json") {
		t.Fatalf("expected application/json content-type, got %q", req.ContentType)
	}

	var decoded struct {
		Query     string                 `json:"query"`
		Variables map[string]interface{} `json:"variables"`
	}
	if err := json.Unmarshal(req.Body, &decoded); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, string(req.Body))
	}
	if decoded.Query != queryParam.Example {
		t.Fatalf("unexpected query: %q", decoded.Query)
	}
	if _, hasCmd := decoded.Variables["cmd"]; hasCmd {
		t.Fatalf("expected other form group variable 'cmd' to be excluded, got %+v", decoded.Variables)
	}
	if decoded.Variables["title"] != "injected-title" {
		t.Fatalf("expected injected title, got %#v", decoded.Variables["title"])
	}
	if idVal, ok := decoded.Variables["id"].(float64); !ok || idVal != 1 {
		t.Fatalf("expected numeric id=1, got %#v", decoded.Variables["id"])
	}
	_ = io.Discard
}
