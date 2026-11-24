// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"conqueror/internal/domain/cloud"
	"conqueror/internal/domain/docker"
	"conqueror/internal/domain/events"
	"conqueror/internal/domain/kubernetes"
	"conqueror/internal/domain/local"
	_ "conqueror/internal/logger"
	"time"
)

func main() {
	startTime := time.Now().UTC().Format(time.RFC3339)
	mode := GetMode()
	events.SetMode(mode)

	events.HandleInfo("----- CONQUEROR v1.2.0 -----", "")
	events.HandleInfo("", "")
	events.HandleInfo("----- [ OS Checks ] -----", "")
	local.GetSystemIdentity()
	local.CheckKernelVersion()
	local.RunningAsRoot()
	local.GetGroups()
	local.IsReadOnlyRootFS()
	local.IsPrivileged()
	local.Capsh()
	local.GetCmdline()
	local.GetEnv()

	events.HandleInfo("", "")
	events.HandleInfo("----- [ Docker Checks ] -----", "")
	isDockerNative := docker.IsDockerEnv()
	if isDockerNative {
		docker.HasDockerSocket()
		docker.HasDockerNetworkServices()
	}

	events.HandleInfo("", "")
	events.HandleInfo("----- [ Kubernetes Checks ] -----", "")
	service := kubernetes.NewService()
	isKubernetes := service.HasApiToken()
	if isKubernetes {
		service.HasDangerousServiceAccount()
		service.HasDangerousRBAC()
	}

	events.HandleInfo("", "")
	events.HandleInfo("----- [ Cloud Checks ] -----", "")
	isRunningInCloud := cloud.IsRunningInCloud()
	if isRunningInCloud {
		cloud.CheckIMDSEndpoints()
	}

	events.HandleMetaInfo("starttime", startTime)
	events.HandleMetaInfo("endtime", time.Now().UTC().Format(time.RFC3339))

	if mode == events.Json {
		events.PrintJson()
	}
}
