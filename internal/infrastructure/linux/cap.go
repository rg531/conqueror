// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package linux

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Dangerous Capability Bits
var capNames = map[uint64]string{
	21: "CAP_SYS_ADMIN",       // The "God Mode" (Mounting, etc.)
	12: "CAP_DAC_OVERRIDE",    // Bypass file read/write/execute checks
	2:  "CAP_DAC_READ_SEARCH", // Bypass file read/directory search checks
	13: "CAP_CHOWN",           // Change file ownership
	17: "CAP_SYS_RAWIO",       // Access physical memory
	18: "CAP_SYS_CHROOT",      // Use chroot (jailbreak)
}

var capEffRegex = regexp.MustCompile(`CapEff:\s+([a-fA-F0-9]+)`)

func GetCapabilities() (string, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "", err
	}
	matches := capEffRegex.FindSubmatch(data)
	if len(matches) < 2 {
		return "not found", nil
	}
	return decode(string(matches[1])), nil
}

func IsCapSysAdmin() (bool, string) {
	// Wir versuchen eine Kernel-Aktion (Remount), die exakt CAP_SYS_ADMIN erfordert.
	err := unix.Mount("/", "/", "", unix.MS_REMOUNT, "")

	// Wenn der Fehler "Permission Denied" (EPERM) ist, fehlen uns die Rechte.
	if err == unix.EPERM {
		return false, "permission denied (EPERM) on live kernel file-system remount"
	} else if err != nil {
		return true, fmt.Sprintf("live kernel file-system remount on '/' was not denied but answered with: %s", err)
	}
	return true, "successfully executed a live kernel file-system remount on '/' (operation allowed)"
}

func decode(hexCaps string) string {
	// Parse Hex-String to Uint64
	caps, err := strconv.ParseUint(hexCaps, 16, 64)
	if err != nil {
		return "invalid hex"
	}

	var found []string
	for bit, name := range capNames {
		// Check if the specific bit is set
		if (caps & (1 << bit)) != 0 {
			found = append(found, name)
		}
	}

	if len(found) == 0 {
		return fmt.Sprintf("none of the top 6 dangerous caps found in CapEff [%d]", caps)
	}
	return strings.Join(found, ", ")
}
