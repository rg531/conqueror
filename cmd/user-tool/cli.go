// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"conqueror/internal/domain/events"
	"os"
)

var args = os.Args[1:]

func GetMode() events.OutputMode {
	for _, arg := range args {
		if arg == "--json" {
			return events.Json
		} else {
			return events.Log
		}
	}
	return events.Log
}
