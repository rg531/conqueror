// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package linux

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func GetKernelVersion() (string, error) {
	if uname_result, err := exec.Command("uname", "-a").Output(); err == nil {
		return strings.TrimSpace(string(uname_result)), nil
	}
	proc_version_result, err := os.ReadFile("/proc/version")
	if err != nil {
		return "", fmt.Errorf("could not get kernel version: %w", err)
	}
	return strings.TrimSpace(string(proc_version_result)), nil
}
