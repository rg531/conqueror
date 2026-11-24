// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package linux

import (
	_ "conqueror/internal/logger"
	"net"
	"os"
	"os/user"
	"strconv"
)

func GetUser() string {
	u, err := user.Current()
	if err != nil {
		// try "os" package in case "os/user" failed.
		return "unknown:" + strconv.Itoa(os.Getuid())
	}
	return u.Username
}

func GetGroups() ([]string, error) {
	// get group-ids as numbers:
	var groups []string
	if u, err := user.Current(); err == nil {
		// try with ""os/user":
		groups, _ = u.GroupIds()
	} else if rawGids, err := os.Getgroups(); err == nil {
		// try with "os":
		for _, id := range rawGids {
			groups = append(groups, strconv.Itoa(id))
		}
	} else {
		return nil, err
	}
	// convert to group names:
	for i, id := range groups {
		if g, err := user.LookupGroupId(id); err == nil {
			groups[i] = g.Name // use group-name as the only information. if there was an error, we just keep the previous info which is GID.
		}
	}
	return groups, nil
}

func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}
	return hostname
}

func GetIpv4Addr() string {
	ipv4Addr := "no-ip"
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			// no loopback and only IPv4:
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ipv4Addr = ipnet.IP.String()
					break // take first match.
				}
			}
		}
	}
	return ipv4Addr
}
