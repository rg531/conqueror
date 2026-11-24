// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"conqueror/internal/domain/events"
	"conqueror/internal/infrastructure/sockets"
	_ "conqueror/internal/logger"
	"strings"
)

func IsDockerEnv() bool {
	proof, success := sockets.IsDockerEnv()
	if success {
		events.HandleMetaInfo("environment", "docker")
		events.HandleInfo("docker environment found", proof)
	} else {
		events.HandleInfo("no docker environment found", proof)
	}
	return success
}
func HasDockerSocket() {
	proof, success := sockets.HasDockerSocket()
	if success {
		events.HandleVulnerability(events.Docker, "docker socket found", "has_docket_socket", proof)
	} else {
		events.HandleInfo("no docker socket found", proof)
	}
}

func HasDockerNetworkServices() {
	hasDockerDaemon()
	hasDockerTLSDaemon()
	hasDockerSwarm()
	hasDockerOverlayNetwork()
	hasSSHService()
}
func hasDockerDaemon() {
	hasSocket, details := sockets.HasLocalPort("2375")
	if hasSocket {
		events.HandleVulnerability(events.Docker, "docker daemon found", "has_docker_socket", details)
	} else {
		gateway_ip := strings.Split(details, ":")[0]
		events.HandleInfo("found gateway IP for docker host", gateway_ip)
		events.HandleInfo("no docker daemon found", details)
	}
}
func hasDockerTLSDaemon() {
	hasSocket, details := sockets.HasLocalPort("2376")
	if hasSocket {
		events.HandleVulnerability(events.Docker, "docker TLS daemon found", "has_docker_tls_daemon", details)
	} else {
		events.HandleInfo("no docker TLS daemon found", details)
	}
}
func hasDockerSwarm() {
	hasSocket, details := sockets.HasLocalPort("2377")
	if hasSocket {
		events.HandleVulnerability(events.Docker, "docker swarm found", "has_docker_swarm", details)
	} else {
		events.HandleInfo("no docker swarm found", details)
	}
}
func hasDockerOverlayNetwork() {
	hasSocket, details := sockets.HasLocalPort("7946")
	if hasSocket {
		events.HandleVulnerability(events.Docker, "docker overlay network found", "has_docker_overlay_network", details)
	} else {
		events.HandleInfo("no docker overlay network found", details)
	}
}
func hasSSHService() {
	hasSocket1, details1 := sockets.HasLocalPort("22")
	hasSocket2, details2 := sockets.HasLocalPort("2222")
	if hasSocket1 {
		events.HandleVulnerability(events.Docker, "SSH service found", "has_ssh_service", details1)
	}
	if hasSocket2 {
		events.HandleVulnerability(events.Docker, "SSH service found", "has_ssh_service", details2)
	}
	if !hasSocket1 && !hasSocket2 {
		events.HandleInfo("no SSH service found", "ports 22,2222 not available")
	}
}
