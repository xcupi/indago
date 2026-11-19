package report

import (
	"bytes"
	"strconv"
	"strings"
)

// ExtractPDFSectionPages parses a Chromium/Skia-generated PDF and maps each
// named destination (e.g. "s1", "s2") to its 1-based page number. Returns nil
// if the bytes are not a PDF or contain no resolvable destinations.
//
// Chromium's --print-to-pdf emits uncompressed indirect objects for the page
// tree (/Catalog -> /Pages -> /Kids) and named destinations (/Dests or
// /Names -> /Dests), so this works with the standard library alone.
func ExtractPDFSectionPages(pdf []byte) map[string]int {
	if !bytes.HasPrefix(pdf, []byte("%PDF")) {
		return nil
	}

	objs := parsePDFObjects(pdf)
	if len(objs) == 0 {
		return nil
	}

	catalogNum := findPDFCatalog(pdf, objs)
	if catalogNum <= 0 {
		return nil
	}
	catalogBody := objs[catalogNum]
	if len(catalogBody) == 0 {
		return nil
	}

	pagesRef, ok := findPDFRef(catalogBody, "/Pages")
	if !ok {
		return nil
	}
	pageOfObj := make(map[int]int)
	pageCount := 0
	walkPDFPages(objs, pagesRef, pageOfObj, &pageCount, make(map[int]bool))
	if len(pageOfObj) == 0 {
		return nil
	}

	destPages := make(map[string]int)

	// Case 1: /Catalog has /Dests (either indirect ref or inline dict), which
	// Chromium/Skia emits for <a href="#id"> / <section id="...">.
	if destsBody, ok := resolvePDFDictField(objs, catalogBody, "/Dests"); ok {
		collectPDFDestsDict(objs, destsBody, pageOfObj, destPages)
	}

	// Case 2: PDF 1.2+ name tree at /Catalog -> /Names -> /Dests.
	if namesBody, ok := resolvePDFDictField(objs, catalogBody, "/Names"); ok {
		if destsRef, ok := findPDFRef(namesBody, "/Dests"); ok {
			walkPDFNameTree(objs, destsRef, pageOfObj, destPages, make(map[int]bool))
		}
	}

	if len(destPages) == 0 {
		return nil
	}
	return destPages
}

// parsePDFObjects scans pdf for "<num> <gen> obj" definitions and stores the
// object header bytes (up to "stream" or "endobj") keyed by object number.
func parsePDFObjects(pdf []byte) map[int][]byte {
	objs := make(map[int][]byte)
	n := len(pdf)
	i := 0
	for i < n {
		// Skip stream payloads so binary data cannot match "N G obj".
		if i+6 <= n && bytes.Equal(pdf[i:i+6], []byte("stream")) && (i == 0 || isPDFDelimOrSpace(pdf[i-1])) {
			if i+6 < n && (pdf[i+6] == '\r' || pdf[i+6] == '\n') {
				end := bytes.Index(pdf[i+6:], []byte("endstream"))
				if end < 0 {
					break
				}
				i = i + 6 + end + len("endstream")
				continue
			}
		}

		if pdf[i] >= '0' && pdf[i] <= '9' && (i == 0 || isPDFDelimOrSpace(pdf[i-1])) {
			objNum, next, ok := parsePDFObjHeader(pdf, i)
			if ok {
				bodyEnd := findPDFObjBodyEnd(pdf, next)
				if bodyEnd > next {
					objs[objNum] = bytes.TrimSpace(pdf[next:bodyEnd])
				}
				i = bodyEnd
				continue
			}
		}
		i++
	}
	return objs
}

func parsePDFObjHeader(pdf []byte, pos int) (objNum, bodyStart int, ok bool) {
	n := len(pdf)
	j := pos
	for j < n && pdf[j] >= '0' && pdf[j] <= '9' {
		j++
	}
	if j == pos || j >= n || !isPDFSpace(pdf[j]) {
		return 0, 0, false
	}
	num, err := strconv.Atoi(string(pdf[pos:j]))
	if err != nil {
		return 0, 0, false
	}
	for j < n && isPDFSpace(pdf[j]) {
		j++
	}
	genStart := j
	for j < n && pdf[j] >= '0' && pdf[j] <= '9' {
		j++
	}
	if j == genStart || j >= n || !isPDFSpace(pdf[j]) {
		return 0, 0, false
	}
	for j < n && isPDFSpace(pdf[j]) {
		j++
	}
	if j+3 <= n && bytes.Equal(pdf[j:j+3], []byte("obj")) && (j+3 == n || isPDFDelimOrSpace(pdf[j+3])) {
		return num, j + 3, true
	}
	return 0, 0, false
}

func findPDFObjBodyEnd(pdf []byte, pos int) int {
	n := len(pdf)
	i := pos
	for i < n {
		switch pdf[i] {
		case '(':
			i = skipPDFString(pdf, i)
		case '%':
			for i < n && pdf[i] != '\n' && pdf[i] != '\r' {
				i++
			}
		default:
			if i+6 <= n && bytes.Equal(pdf[i:i+6], []byte("endobj")) && (i == pos || isPDFDelimOrSpace(pdf[i-1])) && (i+6 == n || isPDFDelimOrSpace(pdf[i+6])) {
				return i
			}
			if i+6 <= n && bytes.Equal(pdf[i:i+6], []byte("stream")) && (i == pos || isPDFDelimOrSpace(pdf[i-1])) && i+6 < n && (pdf[i+6] == '\r' || pdf[i+6] == '\n') {
				return i
			}
			i++
		}
	}
	return n
}

func findPDFCatalog(pdf []byte, objs map[int][]byte) int {
	if idx := bytes.LastIndex(pdf, []byte("trailer")); idx >= 0 {
		if ref, ok := findPDFRef(pdf[idx:], "/Root"); ok {
			return ref
		}
	}
	for _, body := range objs {
		if hasPDFType(body, "/XRef") {
			if ref, ok := findPDFRef(body, "/Root"); ok {
				return ref
			}
		}
	}
	for num, body := range objs {
		if hasPDFType(body, "/Catalog") {
			return num
		}
	}
	return 0
}

func hasPDFType(body []byte, typeName string) bool {
	val, ok := findPDFKeyValue(body, "/Type")
	if !ok {
		return false
	}
	tok, _ := readPDFToken(val, 0)
	return tok == typeName
}

func walkPDFPages(objs map[int][]byte, objNum int, pageOfObj map[int]int, pageCount *int, visited map[int]bool) {
	if visited[objNum] {
		return
	}
	visited[objNum] = true

	body := objs[objNum]
	if len(body) == 0 {
		return
	}
	if kidsBytes, ok := findPDFArray(body, "/Kids"); ok {
		for _, kid := range parsePDFRefs(kidsBytes) {
			walkPDFPages(objs, kid, pageOfObj, pageCount, visited)
		}
		return
	}
	if hasPDFType(body, "/Page") {
		*pageCount++
		pageOfObj[objNum] = *pageCount
	}
}

func collectPDFDestsDict(objs map[int][]byte, dict []byte, pageOfObj map[int]int, out map[string]int) {
	inner, ok := unwrapPDFDict(dict)
	if !ok {
		return
	}
	i := 0
	for i < len(inner) {
		i = skipPDFSpaceAndComments(inner, i)
		if i >= len(inner) {
			break
		}
		if inner[i] != '/' {
			// Unexpected token; advance past it to avoid spinning.
			_, next := readPDFValue(inner, i)
			if next <= i {
				break
			}
			i = next
			continue
		}
		key, next := readPDFToken(inner, i)
		valBytes, afterVal := readPDFValue(inner, next)
		if afterVal <= next {
			break
		}
		i = afterVal

		name := strings.TrimPrefix(key, "/")
		if name == "" {
			continue
		}
		if pageObj, ok := resolvePDFDestPageObj(objs, valBytes); ok {
			if page, exists := pageOfObj[pageObj]; exists && page > 0 {
				out[name] = page
			}
		}
	}
}

func walkPDFNameTree(objs map[int][]byte, objNum int, pageOfObj map[int]int, out map[string]int, visited map[int]bool) {
	if visited[objNum] {
		return
	}
	visited[objNum] = true

	body := objs[objNum]
	if len(body) == 0 {
		return
	}
	if namesArr, ok := findPDFArray(body, "/Names"); ok {
		i := 0
		for i < len(namesArr) {
			i = skipPDFSpaceAndComments(namesArr, i)
			if i >= len(namesArr) {
				break
			}
			keyBytes, next := readPDFValue(namesArr, i)
			if next <= i {
				break
			}
			valBytes, afterVal := readPDFValue(namesArr, next)
			if afterVal <= next {
				break
			}
			i = afterVal

			name := parsePDFStringOrName(keyBytes)
			if name == "" {
				continue
			}
			if pageObj, ok := resolvePDFDestPageObj(objs, valBytes); ok {
				if page, exists := pageOfObj[pageObj]; exists && page > 0 {
					out[name] = page
				}
			}
		}
	}
	if kidsArr, ok := findPDFArray(body, "/Kids"); ok {
		for _, kid := range parsePDFRefs(kidsArr) {
			walkPDFNameTree(objs, kid, pageOfObj, out, visited)
		}
	}
}

func resolvePDFDestPageObj(objs map[int][]byte, val []byte) (int, bool) {
	val = bytes.TrimSpace(val)
	if len(val) == 0 {
		return 0, false
	}
	if val[0] == '[' {
		refs := parsePDFRefs(val[1:])
		if len(refs) > 0 {
			return refs[0], true
		}
		return 0, false
	}
	if ref, ok := parseSinglePDFRef(val); ok {
		target := objs[ref]
		if len(target) == 0 {
			return 0, false
		}
		if target[0] == '[' {
			refs := parsePDFRefs(target[1:])
			if len(refs) > 0 {
				return refs[0], true
			}
		}
		if dArr, ok := findPDFArray(target, "/D"); ok {
			refs := parsePDFRefs(dArr)
			if len(refs) > 0 {
				return refs[0], true
			}
		}
	}
	if dArr, ok := findPDFArray(val, "/D"); ok {
		refs := parsePDFRefs(dArr)
		if len(refs) > 0 {
			return refs[0], true
		}
	}
	return 0, false
}

func resolvePDFDictField(objs map[int][]byte, dict []byte, key string) ([]byte, bool) {
	val, ok := findPDFKeyValue(dict, key)
	if !ok {
		return nil, false
	}
	val = bytes.TrimSpace(val)
	if len(val) >= 2 && val[0] == '<' && val[1] == '<' {
		return val, true
	}
	if ref, ok := parseSinglePDFRef(val); ok {
		body := objs[ref]
		if len(body) > 0 {
			return body, true
		}
	}
	return nil, false
}

func findPDFRef(dict []byte, key string) (int, bool) {
	val, ok := findPDFKeyValue(dict, key)
	if !ok {
		return 0, false
	}
	return parseSinglePDFRef(val)
}

func findPDFArray(dict []byte, key string) ([]byte, bool) {
	val, ok := findPDFKeyValue(dict, key)
	if !ok {
		return nil, false
	}
	val = bytes.TrimSpace(val)
	if len(val) >= 2 && val[0] == '[' && val[len(val)-1] == ']' {
		return val[1 : len(val)-1], true
	}
	return nil, false
}

func findPDFKeyValue(dict []byte, wantKey string) ([]byte, bool) {
	inner, ok := unwrapPDFDict(dict)
	if !ok {
		return nil, false
	}
	i := 0
	for i < len(inner) {
		i = skipPDFSpaceAndComments(inner, i)
		if i >= len(inner) {
			break
		}
		if inner[i] != '/' {
			_, next := readPDFValue(inner, i)
			if next <= i {
				break
			}
			i = next
			continue
		}
		key, next := readPDFToken(inner, i)
		val, afterVal := readPDFValue(inner, next)
		if afterVal <= next {
			break
		}
		if key == wantKey {
			return bytes.TrimSpace(val), true
		}
		i = afterVal
	}
	return nil, false
}

func unwrapPDFDict(b []byte) ([]byte, bool) {
	start := bytes.Index(b, []byte("<<"))
	if start < 0 {
		return nil, false
	}
	end := matchPDFDictEnd(b, start)
	if end <= start+2 {
		return nil, false
	}
	return b[start+2 : end-2], true
}

func matchPDFDictEnd(b []byte, start int) int {
	depth := 0
	i := start
	n := len(b)
	for i < n {
		switch b[i] {
		case '(':
			i = skipPDFString(b, i)
		case '<':
			if i+1 < n && b[i+1] == '<' {
				depth++
				i += 2
				continue
			}
			i++
		case '>':
			if i+1 < n && b[i+1] == '>' {
				depth--
				i += 2
				if depth == 0 {
					return i
				}
				continue
			}
			i++
		default:
			i++
		}
	}
	return n
}

func readPDFValue(b []byte, pos int) ([]byte, int) {
	i := skipPDFSpaceAndComments(b, pos)
	if i >= len(b) {
		return nil, i
	}
	switch b[i] {
	case '<':
		if i+1 < len(b) && b[i+1] == '<' {
			end := matchPDFDictEnd(b, i)
			return b[i:end], end
		}
		end := bytes.IndexByte(b[i:], '>')
		if end < 0 {
			return b[i:], len(b)
		}
		return b[i : i+end+1], i + end + 1
	case '[':
		end := matchPDFArrayEnd(b, i)
		return b[i:end], end
	case '(':
		end := skipPDFString(b, i)
		return b[i:end], end
	default:
		// Could be a scalar token OR an indirect reference "N G R".
		tok1, p1 := readPDFToken(b, i)
		if isDigits(tok1) {
			tok2, p2 := readPDFToken(b, p1)
			if isDigits(tok2) {
				tok3, p3 := readPDFToken(b, p2)
				if tok3 == "R" {
					return b[i:p3], p3
				}
			}
		}
		return b[i:p1], p1
	}
}

func matchPDFArrayEnd(b []byte, start int) int {
	depth := 0
	i := start
	n := len(b)
	for i < n {
		switch b[i] {
		case '(':
			i = skipPDFString(b, i)
		case '[':
			depth++
			i++
		case ']':
			depth--
			i++
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return n
}

func skipPDFString(b []byte, start int) int {
	depth := 0
	i := start
	n := len(b)
	for i < n {
		switch b[i] {
		case '\\':
			i += 2
		case '(':
			depth++
			i++
		case ')':
			depth--
			i++
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return n
}

func readPDFToken(b []byte, pos int) (string, int) {
	i := skipPDFSpaceAndComments(b, pos)
	if i >= len(b) {
		return "", i
	}
	start := i
	if b[i] == '/' {
		i++
	}
	for i < len(b) && !isPDFDelimOrSpace(b[i]) {
		i++
	}
	return string(b[start:i]), i
}

func skipPDFSpaceAndComments(b []byte, pos int) int {
	i := pos
	for i < len(b) {
		if isPDFSpace(b[i]) {
			i++
			continue
		}
		if b[i] == '%' {
			for i < len(b) && b[i] != '\n' && b[i] != '\r' {
				i++
			}
			continue
		}
		break
	}
	return i
}

func parseSinglePDFRef(b []byte) (int, bool) {
	t1, p1 := readPDFToken(b, 0)
	t2, p2 := readPDFToken(b, p1)
	t3, _ := readPDFToken(b, p2)
	if !isDigits(t1) || !isDigits(t2) || t3 != "R" {
		return 0, false
	}
	num, err := strconv.Atoi(t1)
	if err != nil {
		return 0, false
	}
	return num, true
}

func parsePDFRefs(b []byte) []int {
	var refs []int
	i := 0
	for i < len(b) {
		i = skipPDFSpaceAndComments(b, i)
		if i >= len(b) {
			break
		}
		t1, p1 := readPDFToken(b, i)
		if p1 <= i {
			i++
			continue
		}
		if isDigits(t1) {
			t2, p2 := readPDFToken(b, p1)
			if isDigits(t2) {
				t3, p3 := readPDFToken(b, p2)
				if t3 == "R" {
					if num, err := strconv.Atoi(t1); err == nil {
						refs = append(refs, num)
					}
					i = p3
					continue
				}
			}
		}
		i = p1
	}
	return refs
}

func parsePDFStringOrName(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) >= 2 && b[0] == '(' && b[len(b)-1] == ')' {
		return string(b[1 : len(b)-1])
	}
	if len(b) >= 1 && b[0] == '/' {
		return string(b[1:])
	}
	return ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isPDFSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == 0
}

func isPDFDelimOrSpace(c byte) bool {
	if isPDFSpace(c) {
		return true
	}
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}
