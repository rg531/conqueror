// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package linux

import (
	"os"
	"strings"
)

func IsReadOnlyRootFS() (string, bool) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "could not read /proc/self/mountinfo", true
	}

	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		// in /proc/self/mountinfo fields[4] is the mountpoint ("/")
		// and fields[5] are mount-options (e. g. "ro,relatime" or "rw,relatime")
		if len(fields) >= 6 && fields[4] == "/" {
			for _, opt := range strings.Split(fields[5], ",") {
				if opt == "ro" {
					return "root filesystem mounted read-only (ro)", true
				}
			}
			return "root filesystem mounted in read-write (rw) mode according to /proc/self/mountinfo", false
		}
	}

	return "root mountpoint not found in /proc/self/mountinfo", true
}
