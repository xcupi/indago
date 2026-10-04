// Package domain contains Indago's core domain model: generic entities, value
// enums, and lifecycle state machines shared across every engine.
//
// The model is deliberately NOT specific to Reflected XSS. Phase 1 implements
// Reflected XSS, but Stored XSS, DOM XSS, and future engines reuse these same
// types (Endpoint, Parameter, InjectionPoint, TestJob, Finding, Evidence, …).
//
// This package has no dependencies outside the standard library.
package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// ID is an opaque, globally-unique identifier for a domain entity, formatted as
// a canonical UUIDv4 string.
type ID string

// Empty reports whether the ID is unset.
func (id ID) Empty() bool { return id == "" }

// String implements fmt.Stringer.
func (id ID) String() string { return string(id) }

// NewID returns a cryptographically-random UUIDv4 as an ID.
//
// It panics only if the system CSPRNG fails, which indicates a broken
// environment in which continuing would be unsafe.
func NewID() ID {
	id, err := newUUIDv4()
	if err != nil {
		panic(fmt.Sprintf("domain: cannot generate ID: %v", err))
	}
	return ID(id)
}

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Set version (4) and variant (RFC 4122) bits.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	var buf [36]byte
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf[:]), nil
}
