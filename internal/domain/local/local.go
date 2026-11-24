// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"conqueror/internal/domain/events"
	"conqueror/internal/infrastructure/linux"
	_ "conqueror/internal/logger"
	"regexp"
	"slices"
	"strings"
)

var DANGEROUS_OS_GROUP_NAMES = []string{
	"root",            // Highest privilege level, full system control
	"adm",             // Similar to admin/wheel, can read all system logs
	"wheel",           // The sudo equivalent in many distributions (RHEL/Arch/BSD)
	"sudo",            // Allows executing commands as root (Debian/Ubuntu)
	"admin",           // Similar to sudo/wheel in older or specific distributions
	"docker",          // Grants root-equivalent access via the Docker API (Docker escape)
	"containerd",      // Similar to Docker, direct access to the container runtime
	"lxd",             // LXD container manager allows mounting the host disk as root
	"disk",            // Direct read/write access to all raw block devices (e.g., /dev/vda)
	"shadow",          // Allows reading password hashes from /etc/shadow
	"kmem",            // Direct read/write access to kernel memory
	"mem",             // Direct access to physical memory
	"kvm",             // Access to kernel virtualization, potential VM escape vectors
	"libvirt",         // Allows creating VMs with root privileges on the host
	"video",           // Access to GPU/framebuffer (interface for keyloggers/screen sniffing)
	"audio",           // Access to audio devices (microphone eavesdropping without root privileges)
	"input",           // Direct access to input events (allows building keyloggers)
	"tty",             // Access to terminal devices (allows session hijacking/injections)
	"staff",           // Allowed to write to /usr/local (manipulation of system-wide binaries)
	"systemd-journal", // Allows reading all system logs (including sensitive secrets in logs)
}

var DANGEROUS_OS_GROUP_IDS = []string{
	"0",   // root (Full system control)
	"4",   // adm (Similar to admin/wheel, can read all system logs)
	"5",   // tty (Allows terminal session hijacking)
	"6",   // disk (Raw read/write access to physical hard drives)
	"7",   // lp (Printing system, often a vector for local privilege escalation)
	"20",  // dialout (Direct access to serial interfaces)
	"24",  // cdrom (Direct access to optical media)
	"26",  // tape (Direct access to backup drives)
	"27",  // sudo (Debian/Ubuntu standard for root privileges)
	"29",  // audio (Allows covert eavesdropping via microphones)
	"30",  // dip (Direct access to IP network connections/modems)
	"44",  // video (GPU access, enables keyloggers/screen sniffing)
	"42",  // shadow (Allows reading encrypted password hashes)
	"50",  // staff (Allowed to write to/manipulate /usr/local without root privileges)
	"100", // users (Assigned extended shared permissions on some systems)
	"101", // systemd-journal (Allows reading all system logs including secrets)
	"108", // kvm / libvirt (Enables VM escapes to the host)
	"999", // docker / containerd (Standard GID on Debian for root escape)
}

func IsReadOnlyRootFS() {
	proof, success := linux.IsReadOnlyRootFS()
	if success {
		events.HandleInfo("filesystem is readonly", proof)
	} else {
		events.HandleVulnerability(events.OS, "writing to root-fileystem was possible", "is_not_readonlyrootfs", proof)
	}
}
func GetCmdline() {
	cmdline, err := linux.GetCmdline()
	if err != nil {
		events.HandleError("error getting cmdline", err)
	} else {
		events.HandleInfo("/proc/self/cmdline detected", cmdline)
	}
}

func GetEnv() {
	env := linux.GetEnv()
	if len(env) == 0 {
		events.HandleError("no environment variables found", nil)
	} else {
		events.HandleInfo("environment variables:", "")
		for _, variable := range env {
			events.HandleInfo("-> "+variable, "")
		}
	}
	// detect sensitive info:
	var secretPattern = regexp.MustCompile(`(?i)(password|secret|token|api|key|passwd|credential|private)`)
	for _, env := range env {
		// split on first "=":
		pair := strings.SplitN(env, "=", 2)
		if len(pair) < 2 {
			continue // ignore garbage
		}
		key := pair[0]
		//value := pair[1]

		if secretPattern.MatchString(key) {
			maskedValue := "**************"
			events.HandleVulnerability(events.OS, "found possible secret in environment variable", "has_secret_in_env", key+":"+maskedValue)
		}
	}
}

func GetSystemIdentity() {
	events.HandleMetaInfo("containername", linux.GetHostname())
	events.HandleMetaInfo("ipv4", linux.GetIpv4Addr())
	events.HandleMetaInfo("user", linux.GetUser())
}

func CheckKernelVersion() {
	version, err := linux.GetKernelVersion()
	if err != nil {
		events.HandleError("error getting kernel version", err)
	} else {
		events.HandleMetaInfo("kernel", version)
		events.HandleInfo("kernel version detected", version)
	}
}

func RunningAsRoot() {
	username := linux.GetUser()
	if username == "root" || username == "0" {
		events.HandleVulnerability(events.OS, "running as root", "running_as_root", username)
	} else {
		events.HandleInfo("not running as root", username)
	}
}

func GetGroups() {
	groups, err := linux.GetGroups()
	if err != nil {
		events.HandleError("could not get groups", err)
	} else {
		events.HandleInfo("user groups found", strings.Join(groups, ", "))
		for _, group := range groups {
			// check both NAME/GID in parallel which is easier then detecting the type:
			if slices.Contains(DANGEROUS_OS_GROUP_NAMES, group) {
				events.HandleVulnerability(events.OS, "found dangerous group", "dangerous_os_group", group)
			}
			if slices.Contains(DANGEROUS_OS_GROUP_IDS, group) {
				events.HandleVulnerability(events.OS, "found dangerous group by GID", "dangerous_os_group", group)
			}
		}
	}
}

func IsPrivileged() {
	success, proof := linux.IsCapSysAdmin()
	if success {
		events.HandleVulnerability(events.OS, "privileged container found", "is_privileged", proof)
	} else {
		events.HandleInfo("likely not in a privileged container.", proof)
	}
}

func Capsh() {
	caps, err := linux.GetCapabilities()
	if err != nil {
		events.HandleError("could not determine kernel capabilities", err)
	}
	if strings.Contains(caps, "CAP_") {
		events.HandleVulnerability(events.OS, "found dangerous capabilites", "has_dangerous_cap", caps)
	} else {
		events.HandleInfo("no dangerous capabilities", caps)
	}
}
