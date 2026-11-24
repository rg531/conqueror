// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	"conqueror/internal/domain/events"
	"conqueror/internal/infrastructure/kubernetes"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"

	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func checkPodsNamespace(pod *Pod) {
	events.HandleMetaInfo("namespace", pod.Namespace)
	events.HandleInfo("checking the pods namespace "+pod.Namespace+":", "")
	checkRBAC(pod.Namespace, pod)
}

func checkClusterRolesForPod(pod *Pod) {
	// the trick is to request RBAC for non-existent namespace;
	// API will return clusterroles if exist (because API believes clusterroles are applicable for every namespace, even non-existent ones).
	events.HandleInfo("checking for clusterroles using a fake namespace name:", "")
	checkRBAC("fake-namespace-123-does-not-exist-we-just-want-our-cluster-rules", pod)
}

func escalateToClusterLevel(pod *Pod) {
	events.HandleInfo("trying to escalate to cluster level", "")
	if pod.HasClusterRuleFor("list", "clusterrolebindings") {
		events.HandleInfo("checking dangerous clusterrolebindings", "")
		analyzeClusterRoleBindings(pod)
	} else {
		events.HandleInfo("not allowed to list clusterrolebindings", "")
	}
	if pod.HasClusterRuleFor("list", "clusterroles") {
		events.HandleInfo("checking dangerous clusterroles", "")
		analyzeClusterRoles()
	} else {
		events.HandleInfo("not allowed to list clusterroles", "")
	}
}

func analyzeClusterRoles() {
	clusterRoles, err := kubernetes.ListClusterRoles()
	if err != nil {
		events.HandleError("failed to list clusterroles", err)
	} else {
		for _, clusterRole := range clusterRoles {
			if isHarmlessClusterRole(clusterRole) { // reduce the noise.
				continue
			}
			for _, clusterRule := range clusterRole.Rules {
				rule := FromPolicyRule(clusterRule)
				if rule.severity == SeverityHarmless {
					continue
				}
				proof := fmt.Sprintf("roleName=%s, %s", clusterRole.Name, rule.Proof())
				switch rule.severity {
				case SeverityCritical:
					events.HandleVulnerability(events.Kubernetes, "high-risk non-standard clusterrole found", "high_risk_k8s_clusterrole", proof)
				case SeverityModerate:
					events.HandleVulnerability(events.Kubernetes, "low-risk non-standard clusterrole found", "low_risk_k8s_clusterrole", proof)
				}
			}
		}
	}
}

// report all non-standard clusterrolebindings and their clusterrole description.
func analyzeClusterRoleBindings(pod *Pod) {
	bindings, err := kubernetes.GetClusterRoleBindings()
	if err != nil {
		events.HandleError("failed to list clusterrolebindings", err)
	} else {
		for _, binding := range bindings {
			policyRules, err := kubernetes.GetClusterRole(binding.RoleRef.Name)
			if isHarmlessClusterRoleBinding(binding) {
				continue
			}
			for _, subject := range binding.Subjects {
				if pod.HasSubject(subject) || isHarmlessSubject(subject) {
					continue // ignore bindings that were alreay reported during RBAC scan of pod (compared via subject).
				} else {
					reportClusterRoleBinding(err, binding, subject, policyRules)
				}
			}
		}
	}
}

func reportClusterRoleBinding(err error, binding rbacv1.ClusterRoleBinding, subject rbacv1.Subject, policyRules []rbacv1.PolicyRule) {
	if err != nil {
		// report binding without role details:
		events.HandleError("found clusterrolebinding but could not load respective clusterrole", err)
		proof := fmt.Sprintf("binding=%s, subject=%s, roleref=%s, error=[could not get clusterroles by roleref]", binding.Name, formatSubject(subject), binding.RoleRef.Name)
		events.HandleVulnerability(events.Kubernetes, "non-standard clusterrolebinding found", "non_standard_k8s_clusterrolebinding", proof)
	} else {
		// report binding with role details:
		for _, policyRule := range policyRules {
			rule := FromPolicyRule(policyRule)
			if rule.severity == SeverityHarmless {
				continue
			}
			proof := fmt.Sprintf("binding=%s, subject=%s, roleref=%s, %s", binding.Name, formatSubject(subject), binding.RoleRef.Name, rule.Proof())
			switch rule.severity {
			case SeverityCritical:
				events.HandleVulnerability(events.Kubernetes, "high-risk non-standard clusterrolebinding found", "high_risk_k8s_clusterrolebinding", proof)
			case SeverityModerate:
				events.HandleVulnerability(events.Kubernetes, "low-risk non-standard clusterrolebinding found", "low_risk_k8s_clusterrolebinding", proof)
			}
		}
	}
}

func isHarmlessClusterRole(clusterRole rbacv1.ClusterRole) bool {
	return (strings.HasPrefix(clusterRole.Name, "system:") || strings.HasPrefix(clusterRole.Name, "system-")) && clusterRole.Name != "system:masters" ||
		clusterRole.Name == "view" ||
		clusterRole.Name == "flannel" ||
		clusterRole.Name == "local-path-provisioner-role"
}

func isHarmlessSubject(subject rbacv1.Subject) bool {
	return subject.Namespace == "kube-system" || (strings.HasPrefix(subject.Name, "system:") && subject.Name != "system:serviceaccounts")
}

func isHarmlessClusterRoleBinding(binding rbacv1.ClusterRoleBinding) bool {
	return binding.RoleRef.Name == "system:cluster-trust-bundle-discovery" ||
		binding.RoleRef.Name == "system:service-account-issuer-discovery" ||
		binding.RoleRef.Name == "system:public-info-viewer" ||
		(binding.Name == "local-path-provisioner-bind" && binding.RoleRef.Name == "local-path-provisioner-role")
}

func formatSubject(subject rbacv1.Subject) string {
	if subject.Namespace != "" {
		return fmt.Sprintf("%s:%s:%s", subject.Kind, subject.Namespace, subject.Name)
	} else {
		return fmt.Sprintf("%s:%s", subject.Kind, subject.Name)
	}
}

// contains commented out draft for multithreading, which would be useful when we check 30+ namespaces...
func escalateToOtherNamespaces(pod *Pod) {
	//var wg sync.WaitGroup
	if pod.HasClusterRuleFor("list", "namespaces") {
		namespaces := kubernetes.GetNamespaces()
		for _, namespace := range namespaces {
			if namespace != pod.Namespace {
				events.HandleInfo("trying to escalate to namespace "+namespace, "")
				//checkRBACAsync(namespace, &wg)
				checkRBAC(namespace, pod)
			}
		}
		//wg.Wait()
	} else {
		// we cannot list namespaces so we try a couple of common ones:
		common_namespaces := []string{"default", "test", "dev", "debug", "admin", "test2", "demo", "poc", "restricted", "unrestricted"}
		events.HandleInfo("trying to escalate to other namespaces using common names: "+strings.Join(common_namespaces, ", "), "")
		for _, namespace := range common_namespaces {
			if namespace != pod.Namespace {
				//checkRBACAsync(namespace, &wg)
				checkRBAC(namespace, pod)
			}
		}
		//wg.Wait()
	}
}

// prepared but not used atm.
func checkRBACAsync(namespace string, pod *Pod, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		checkRBAC(namespace, pod)
	}()
}

// main logic to evaluate RBAC permissions, first load RBAC for a given namespace, then evaluate it, and if possible dig deeper with found privileges:
func checkRBAC(namespace string, pod *Pod) {
	rbac, err := kubernetes.GetRBAC(namespace)
	if err != nil {
		events.HandleError("error loading RBAC from kubernetes API for namespace "+namespace, err)
		return
	}

	potentialClusterRules := []Rule{}
	isFirstRun := len(pod.ClusterRules) == 0 // first run uses a non-existent dummy namespace to discover cluster-wide rules
	isRealNamespace := !isFirstRun

	if isFirstRun { // NonResourceRules are cluster-scoped so we only check on first run:
		for _, rule := range rbac.NonResourceRules {
			checkNonResourceURLs(rule, namespace)
		}
	}

	// main logic for checking rules -- cluster or namespace scoped:
	for _, resourceRule := range rbac.ResourceRules {
		rule := Rule{}
		// convert kubernetes object to domain object:
		if isFirstRun {
			rule = FromResourceRule(resourceRule, "clusterrole")
		} else {
			rule = FromResourceRule(resourceRule, namespace)
		}
		slog.Debug(fmt.Sprintf("isFirstRun=%t, rule=%v", isFirstRun, resourceRule))

		// filter results:
		if rule.severity == SeverityHarmless || // filter out noise.
			slices.ContainsFunc(pod.ClusterRules, rule.Equal) || // ignore already collected clusterrules for runs after 1st.
			slices.ContainsFunc(potentialClusterRules, rule.Equal) { // ignore already collected clusterrules for 1st run.
			slog.Debug(fmt.Sprintf("rule=%s", rule.ToString()))
			continue
		}

		// found an uncollected clusterrule:
		if isFirstRun {
			potentialClusterRules = append(potentialClusterRules, rule)
		}

		// data exfiltration:
		if isRealNamespace && rule.Allows("list", "secrets") {
			extractSecrets(namespace)
		}
		// ------------------------------------------
		// **TODO** man könnte noch get configmaps hinzufügen als low issue oder TODO.
		// außerdem gäbe es noch edge cases: ich darf nicht listen, aber darf getten
		// 		-> 1. resource names checken (zu 99% leer) aber wenn was drin steht kann ich das lesen
		// 		-> 2. jetzt wirds wild, fiktive secrets versuchen zu lesen!
		// ------------------------------------------

		if isFirstRun || rule.severity == SeverityCritical {
			// during first run we only find potential clusterroles for the pod, so first-run findings are always critical:
			events.HandleVulnerability(events.Kubernetes, "critical RBAC violations found", "critical_k8s_rbac_violation", rule.Proof())
		} else if rule.severity == SeverityModerate {
			events.HandleVulnerability(events.Kubernetes, "moderate RBAC violations found", "moderate_k8s_rbac_violation", rule.Proof())
		}
	}
	// store potential clusterrules during runtime for further function calls, if not done yet:
	if isFirstRun {
		if len(potentialClusterRules) == 0 {
			// we did not find any clusterroles on first run, we insert a default so we will not encounter the check again:
			pod.ClusterRules = append(pod.ClusterRules, Rule{})
		} else {
			pod.ClusterRules = potentialClusterRules
		}
	}
}

func checkNonResourceURLs(r authorizationv1.NonResourceRule, namespace string) {
	if slices.Contains(r.Verbs, "get") && len(r.Verbs) == 1 {
		// filter out the noise:
		if len(r.NonResourceURLs) == 11 && slices.Contains(r.NonResourceURLs, "/openapi/*") {
			return
		}
		if len(r.NonResourceURLs) == 5 && slices.Contains(r.NonResourceURLs, "/healthz") {
			return
		}
		if len(r.NonResourceURLs) == 4 && slices.Contains(r.NonResourceURLs, "/openid/v1/jwks") {
			return
		}
	}
	// atm we do not check those URLs except for excluding "noise"/harmless ones, they might range from moderate to critical:
	proof := fmt.Sprintf("verb=%s, resourceURLs=%s, namespace=%s TODO='check priority'", r.Verbs, strings.Join(r.NonResourceURLs, ", "), namespace)
	events.HandleVulnerability(events.Kubernetes, "accessible kuberneres resource URL found", "accessible_k8s_resource_url", proof)
}

func extractSecrets(namespace string) {
	events.HandleInfo("checking for existing secrets", "")
	secrets, err := kubernetes.GetSecrets(namespace)
	if err != nil {
		events.HandleError("failed to list secrets in namespace "+namespace, err)
	} else {
		for _, secret := range secrets {
			keys := strings.Join(slices.Collect(maps.Keys(secret.Data)), ",")
			events.HandleVulnerability(events.Kubernetes, "kubernetes secret found", "access_k8s_secrets", fmt.Sprintf("secret=%s, namespace=%s, keys=%s", secret.Name, namespace, keys))
		}
	}
}
