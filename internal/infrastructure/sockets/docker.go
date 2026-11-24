// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package sockets

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const DEFAULT_GATEWAY_IP = "172.17.0.1"
const ENV_PATH = "/.dockerenv"

var SOCKET_PATHS = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/var/run/dockershim.sock",
	"/home/developer/docker.sock",
}

var linux_gateway_ip string

func GetLinuxGatewayIP() string {
	return linux_gateway_ip
}

func IsDockerEnv() (string, bool) {
	_, err := os.Stat(ENV_PATH)
	if err != nil {
		return ENV_PATH + " not found", false
	} else {
		return ENV_PATH + " found", true
	}
}
func HasDockerSocket() (string, bool) {
	for _, path := range SOCKET_PATHS {
		if fileExists(path) {
			return path + " found", true
		}
	}
	return "docker socket not found in " + strings.Join(SOCKET_PATHS, ","), false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		return false
	} else {
		return true
	}
}

func HasLocalPort(port string) (bool, string) {
	addr := getLinuxGatewayIP() + ":" + port
	timeout := 300 * time.Millisecond
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		conn.Close()
		return true, addr
	}
	return false, addr + " not available"
}

func getLinuxGatewayIP() string {
	if linux_gateway_ip != "" {
		return linux_gateway_ip
	}
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return setLinuxGatewayIP(DEFAULT_GATEWAY_IP)
	}
	// split and iterate over content:
	lines := strings.Split(string(data), "\n")
	for i := 1; i < len(lines); i++ {
		fields := strings.Fields(lines[i])
		// look for Destination (field[1]) = 00000000 and take field[2] (Gateway to host)
		if len(fields) >= 3 && fields[1] == "00000000" {
			ipHex := fields[2] // e.g. "010011AC"
			decoded, err := hex.DecodeString(ipHex)
			if err != nil || len(decoded) != 4 {
				return setLinuxGatewayIP(DEFAULT_GATEWAY_IP)
			} else {
				return setLinuxGatewayIP(fmt.Sprintf("%d.%d.%d.%d", decoded[3], decoded[2], decoded[1], decoded[0]))
			}
		}
	}
	return setLinuxGatewayIP(DEFAULT_GATEWAY_IP)
}

func setLinuxGatewayIP(ip string) string {
	linux_gateway_ip = ip
	return ip
}
