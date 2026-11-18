package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/indago/indago/internal/domain"
	"github.com/indago/indago/internal/httpengine"
)

const graphQLIntrospectionQuery = `{ __schema { queryType { name } mutationType { name } types { kind name enumValues { name } fields(includeDeprecated: true) { name args { name type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }`

type gqlIntrospectionResponse struct {
	Data struct {
		Schema *gqlSchema `json:"__schema"`
	} `json:"data"`
}

type gqlSchema struct {
	QueryType    *gqlNamedRef `json:"queryType"`
	MutationType *gqlNamedRef `json:"mutationType"`
	Types        []gqlType    `json:"types"`
}

type gqlNamedRef struct {
	Name string `json:"name"`
}

type gqlType struct {
	Kind       string         `json:"kind"`
	Name       string         `json:"name"`
	EnumValues []gqlNamedRef  `json:"enumValues"`
	Fields     []gqlField     `json:"fields"`
}

type gqlField struct {
	Name string       `json:"name"`
	Args []gqlArg     `json:"args"`
	Type *gqlTypeRef  `json:"type"`
}

type gqlArg struct {
	Name string      `json:"name"`
	Type *gqlTypeRef `json:"type"`
}

type gqlTypeRef struct {
	Kind   string      `json:"kind"`
	Name   string      `json:"name"`
	OfType *gqlTypeRef `json:"ofType"`
}

type gqlOperation struct {
	Group string
	Query string
	Vars  map[string]string
}

// introspectGraphQLEndpoints runs GraphQL schema introspection against every
// known GraphQL endpoint in scope and registers each Query/Mutation operation
// with arguments as a POST JSON FormGroup so injection engines test variables.
func (s *wellKnownSource) introspectGraphQLEndpoints(ctx context.Context, in Input, sink Sink, seen map[string]bool) error {
	var candidates []string
	if l, ok := sink.(endpointLookup); ok {
		l.AnyEndpoint(func(rawURL string) bool {
			if looksLikeGraphQLEndpointURL(rawURL) {
				candidates = append(candidates, rawURL)
			}
			return false
		})
	}
	for _, seed := range in.SeedURLs {
		if looksLikeGraphQLEndpointURL(seed) {
			candidates = append(candidates, seed)
		}
	}
	for _, rawURL := range candidates {
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		u.RawQuery = ""
		u.Fragment = ""
		info, err := Normalize(u.String())
		if err != nil || seen["gql-introspect:"+info.Canonical] {
			continue
		}
		if !in.Scope.Permits(info.Canonical).Allowed {
			continue
		}
		if !allowFetch(sink, info.Canonical, domain.SourceWellKnown, domain.MethodPOST) {
			continue
		}
		seen["gql-introspect:"+info.Canonical] = true

		if err := in.wait(ctx); err != nil {
			return err
		}
		body, err := json.Marshal(map[string]string{"query": graphQLIntrospectionQuery})
		if err != nil {
			continue
		}
		resp, err := s.engine.Do(ctx, &httpengine.Request{
			Method:      "POST",
			URL:         info.Canonical,
			ContentType: "application/json",
			Body:        body,
		})
		if err != nil || resp == nil || resp.Status < 200 || resp.Status >= 400 || len(resp.Body) == 0 {
			continue
		}
		ops := parseGraphQLIntrospectionOps(resp.Body)
		if len(ops) == 0 {
			continue
		}
		if _, err := sink.AddEndpoint(ctx, EndpointCandidate{
			URL:         info.Canonical,
			Method:      domain.MethodPOST,
			ContentType: "application/json",
			Source:      domain.SourceWellKnown,
		}); err != nil {
			return err
		}
		for _, op := range ops {
			if err := sink.AddParameter(ctx, ParamCandidate{
				EndpointURL:    info.Canonical,
				EndpointMethod: domain.MethodPOST,
				Name:           "query",
				Location:       domain.LocationJSON,
				Example:        op.Query,
				FormGroup:      op.Group,
				Source:         domain.SourceWellKnown,
			}); err != nil {
				return err
			}
			for argName, argVal := range op.Vars {
				if err := sink.AddParameter(ctx, ParamCandidate{
					EndpointURL:    info.Canonical,
					EndpointMethod: domain.MethodPOST,
					Name:           "variables." + argName,
					Location:       domain.LocationJSON,
					Example:        argVal,
					FormGroup:      op.Group,
					Source:         domain.SourceWellKnown,
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func parseGraphQLIntrospectionOps(raw []byte) []gqlOperation {
	var parsed gqlIntrospectionResponse
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.Data.Schema == nil {
		return nil
	}
	schema := parsed.Data.Schema
	typeMap := make(map[string]*gqlType, len(schema.Types))
	for i := range schema.Types {
		t := &schema.Types[i]
		if t.Name != "" {
			typeMap[t.Name] = t
		}
	}

	type rootSpec struct {
		kind string
		name string
	}
	var roots []rootSpec
	if schema.QueryType != nil && schema.QueryType.Name != "" {
		roots = append(roots, rootSpec{kind: "query", name: schema.QueryType.Name})
	}
	if schema.MutationType != nil && schema.MutationType.Name != "" {
		roots = append(roots, rootSpec{kind: "mutation", name: schema.MutationType.Name})
	}

	var ops []gqlOperation
	for _, root := range roots {
		rt := typeMap[root.name]
		if rt == nil {
			continue
		}
		for _, field := range rt.Fields {
			if strings.HasPrefix(field.Name, "__") || len(field.Args) == 0 {
				continue
			}
			varDecls := make([]string, 0, len(field.Args))
			argBinds := make([]string, 0, len(field.Args))
			vars := make(map[string]string, len(field.Args))
			for _, arg := range field.Args {
				typeStr := formatGQLTypeRef(arg.Type)
				if typeStr == "" {
					continue
				}
				varDecls = append(varDecls, fmt.Sprintf("$%s: %s", arg.Name, typeStr))
				argBinds = append(argBinds, fmt.Sprintf("%s: $%s", arg.Name, arg.Name))
				vars[arg.Name] = defaultGQLArgValue(arg.Type, typeMap)
			}
			if len(varDecls) == 0 {
				continue
			}
			sel := buildGQLSelectionSet(field.Type, typeMap)
			queryStr := fmt.Sprintf("%s(%s) { %s(%s)%s }",
				root.kind,
				strings.Join(varDecls, ", "),
				field.Name,
				strings.Join(argBinds, ", "),
				sel,
			)
			ops = append(ops, gqlOperation{
				Group: "gql:" + root.kind + ":" + field.Name,
				Query: queryStr,
				Vars:  vars,
			})
		}
	}
	return ops
}

func formatGQLTypeRef(t *gqlTypeRef) string {
	if t == nil {
		return ""
	}
	switch t.Kind {
	case "NON_NULL":
		inner := formatGQLTypeRef(t.OfType)
		if inner == "" {
			return ""
		}
		return inner + "!"
	case "LIST":
		inner := formatGQLTypeRef(t.OfType)
		if inner == "" {
			return ""
		}
		return "[" + inner + "]"
	default:
		return t.Name
	}
}

func unwrapGQLNamedType(t *gqlTypeRef) string {
	for t != nil {
		if t.Name != "" {
			return t.Name
		}
		t = t.OfType
	}
	return ""
}

func isGQLListType(t *gqlTypeRef) bool {
	for t != nil {
		if t.Kind == "LIST" {
			return true
		}
		if t.Kind == "NON_NULL" {
			t = t.OfType
			continue
		}
		return false
	}
	return false
}

func defaultGQLArgValue(t *gqlTypeRef, typeMap map[string]*gqlType) string {
	if isGQLListType(t) {
		return "[]"
	}
	name := unwrapGQLNamedType(t)
	switch name {
	case "Int", "ID":
		return "1"
	case "Float":
		return "1.0"
	case "Boolean":
		return "true"
	case "String":
		return "indago"
	}
	if gt := typeMap[name]; gt != nil && gt.Kind == "ENUM" && len(gt.EnumValues) > 0 {
		return gt.EnumValues[0].Name
	}
	return "indago"
}

func buildGQLSelectionSet(t *gqlTypeRef, typeMap map[string]*gqlType) string {
	name := unwrapGQLNamedType(t)
	if name == "" {
		return ""
	}
	gt := typeMap[name]
	if gt == nil || gt.Kind == "SCALAR" || gt.Kind == "ENUM" {
		return ""
	}
	if gt.Kind != "OBJECT" && gt.Kind != "INTERFACE" {
		return " { __typename }"
	}
	var picked []string
	for _, f := range gt.Fields {
		if strings.HasPrefix(f.Name, "__") || len(f.Args) > 0 {
			continue
		}
		fn := unwrapGQLNamedType(f.Type)
		ft := typeMap[fn]
		if ft == nil || ft.Kind == "SCALAR" || ft.Kind == "ENUM" || fn == "String" || fn == "Int" || fn == "Boolean" || fn == "ID" || fn == "Float" {
			picked = append(picked, f.Name)
			if len(picked) >= 5 {
				break
			}
		}
	}
	if len(picked) == 0 {
		return " { __typename }"
	}
	return " { " + strings.Join(picked, " ") + " }"
}
