package discovery

import (
	"testing"
)

func TestParseGraphQLIntrospectionOps(t *testing.T) {
	raw := []byte(`{
		"data": {
			"__schema": {
				"queryType": {"name": "Query"},
				"mutationType": {"name": "Mutations"},
				"types": [
					{
						"kind": "OBJECT",
						"name": "Query",
						"fields": [
							{
								"name": "systemDiagnostics",
								"args": [
									{"name": "username", "type": {"kind": "SCALAR", "name": "String"}},
									{"name": "cmd", "type": {"kind": "SCALAR", "name": "String"}}
								],
								"type": {"kind": "SCALAR", "name": "String"}
							},
							{
								"name": "paste",
								"args": [
									{"name": "id", "type": {"kind": "SCALAR", "name": "Int"}},
									{"name": "title", "type": {"kind": "SCALAR", "name": "String"}}
								],
								"type": {"kind": "OBJECT", "name": "PasteObject"}
							},
							{
								"name": "pastes",
								"args": [],
								"type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "PasteObject"}}
							}
						]
					},
					{
						"kind": "OBJECT",
						"name": "Mutations",
						"fields": [
							{
								"name": "createPaste",
								"args": [
									{"name": "title", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "String"}}},
									{"name": "public", "type": {"kind": "SCALAR", "name": "Boolean"}}
								],
								"type": {"kind": "OBJECT", "name": "PasteObject"}
							}
						]
					},
					{
						"kind": "OBJECT",
						"name": "PasteObject",
						"fields": [
							{"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "Int"}},
							{"name": "title", "args": [], "type": {"kind": "SCALAR", "name": "String"}}
						]
					}
				]
			}
		}
	}`)

	ops := parseGraphQLIntrospectionOps(raw)
	if len(ops) != 3 {
		t.Fatalf("expected 3 ops, got %d: %+v", len(ops), ops)
	}
	if ops[0].Group != "gql:query:systemDiagnostics" {
		t.Fatalf("unexpected first op group: %s", ops[0].Group)
	}
	if ops[0].Vars["cmd"] != "indago" {
		t.Fatalf("expected String default 'indago', got %q", ops[0].Vars["cmd"])
	}
	if ops[1].Group != "gql:query:paste" || ops[1].Vars["id"] != "1" {
		t.Fatalf("unexpected second op: %+v", ops[1])
	}
	if ops[2].Group != "gql:mutation:createPaste" || ops[2].Vars["public"] != "true" {
		t.Fatalf("unexpected third op: %+v", ops[2])
	}
}
