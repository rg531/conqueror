// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package linux

import (
	"os"
)

func GetEnv() []string {
	return os.Environ()
}
