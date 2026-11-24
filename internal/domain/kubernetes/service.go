// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	"conqueror/internal/domain/events"
	"conqueror/internal/infrastructure/kubernetes"
	"slices"
)

//
// main service for kubernetes checks.
//

var DANGEROUS_SERVICE_ACCOUNTS = []string{"admin", "root", "superuser", "kube-proxy"}

type Service struct {
	pod *Pod
}

func NewService() *Service {
	kubernetes.Init()

	return &Service{
		pod: &Pod{},
	}
}

func (s *Service) HasApiToken() bool {
	proof, success := kubernetes.HasK8sToken()
	if success {
		events.HandleVulnerability(events.Kubernetes, "Kubernetes API token found", "has_k8s_api_token", proof)
		events.HandleMetaInfo("environment", "kubernetes")
	} else {
		events.HandleInfo("no kubernetes API token found", proof)
	}
	proof, success = kubernetes.HasK8sNamespace()
	if success {
		events.HandleInfo("kubernetes namespace found", proof)
		s.pod.Namespace = proof
	} else {
		events.HandleInfo("no kubernetes namespace found", proof) //
	}
	return success
}

func (s *Service) HasDangerousServiceAccount() {
	thisAccount := kubernetes.Whoami()
	events.HandleMetaInfo("serviceaccount", thisAccount)
	s.pod.ServiceAccount = thisAccount
	if thisAccount == "default" {
		events.HandleVulnerability(events.Kubernetes, "running with default service-account", "default_k8s_serviceaccount", thisAccount)
		return
	}
	if slices.Contains(DANGEROUS_SERVICE_ACCOUNTS, thisAccount) {
		events.HandleVulnerability(events.Kubernetes, "running with dangerous service-account", "dangerous_k8s_serviceaccount", thisAccount)
		return
	}
	events.HandleInfo("found service-account", thisAccount)
}

func (s *Service) HasDangerousRBAC() {
	checkClusterRolesForPod(s.pod) // check potential clusterrules assigned to the pod.
	checkPodsNamespace(s.pod)
	escalateToOtherNamespaces(s.pod) // check other namespaces.
	escalateToClusterLevel(s.pod)    // try to list all clusterules (also foreign ones, not only the pod ones) and analyze them.
}
