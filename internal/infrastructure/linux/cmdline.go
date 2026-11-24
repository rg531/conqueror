// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package linux

import (
	"os"
)

func GetCmdline() (string, error) {
	data, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		return "", err
	} else {
		return string(data), nil
	}
}
