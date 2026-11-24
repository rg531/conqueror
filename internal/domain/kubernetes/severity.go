// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package kubernetes

type Severity int

const (
	SeverityHarmless Severity = iota
	SeverityModerate
	SeverityCritical
)

//
// encapsulates severity of a kubernetes rule.
//

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityModerate:
		return "MODERATE"
	default:
		return "HARMLESS"
	}
}
