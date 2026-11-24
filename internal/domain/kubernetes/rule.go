// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	"fmt"
	"slices"
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

//
// encapsulates a kubernetes rule which can be a rule for a regular RBAC role (e.g. "list configmaps") or a clusterole.
//

type Rule struct {
	APIGroups     []string
	Verbs         []string
	Resources     []string
	ResourceNames []string
	Scope         string // namespace [name] or "clusterrole" (for clusterroless)
	severity      Severity
}

// constructors:
func FromResourceRule(r authorizationv1.ResourceRule, namespace string) Rule {
	rule := Rule{Verbs: r.Verbs, APIGroups: r.APIGroups, Resources: r.Resources, ResourceNames: r.ResourceNames, Scope: namespace}
	rule.setSeverity()
	return rule
}
func FromPolicyRule(p rbacv1.PolicyRule) Rule {
	rule := Rule{Verbs: p.Verbs, APIGroups: p.APIGroups, Resources: p.Resources, ResourceNames: p.ResourceNames, Scope: "clusterrole"}
	rule.setSeverity()
	return rule
}

func (r Rule) Allows(verb string, resource string) bool {
	return slices.Contains(r.Verbs, verb) && slices.Contains(r.Resources, resource)
}

// for proof of vulnerabilities:
func (r Rule) Proof() string {
	extra_info := ""
	if len(r.ResourceNames) > 0 {
		extra_info += ", resourceName=" + join(r.ResourceNames)
	}
	if len(r.APIGroups) > 0 && r.APIGroups[0] != "" {
		extra_info += ", apiGroups=" + join(r.APIGroups)
	}
	if r.isClusterScoped() {
		return fmt.Sprintf("verb=%s, resource=%s, scope=%s%s", join(r.Verbs), join(r.Resources), r.Scope, extra_info)
	} else {
		return fmt.Sprintf("verb=%s, resource=%s, scope=namespaced[%s]%s", join(r.Verbs), join(r.Resources), r.Scope, extra_info)
	}
}

func (r Rule) Equal(other Rule) bool {
	return slices.Equal(r.APIGroups, other.APIGroups) &&
		slices.Equal(r.Verbs, other.Verbs) &&
		slices.Equal(r.Resources, other.Resources) &&
		slices.Equal(r.ResourceNames, other.ResourceNames)
}

// for debug logs:
func (r Rule) ToString() string {
	return fmt.Sprintf("APIGroups=%s, Verbs=%s, Resources=%s, ResourceNames=%s, Severity=%s",
		join(r.APIGroups), join(r.Verbs), join(r.Resources), join(r.ResourceNames), r.severity)
}

func (r *Rule) setSeverity() {
	if r.isHarmless() {
		r.severity = SeverityHarmless
	} else if r.isCritical() {
		r.severity = SeverityCritical
	} else {
		r.severity = SeverityModerate
	}
}

// true: critical violaation, false: moderate violation
func (r Rule) isCritical() bool {
	if slices.Contains(r.Resources, "secrets") || slices.Contains(r.Resources, "*") {
		return true // all operations on secrets are critical, also list/get.
	}
	for _, v := range r.Verbs {
		if v == "create" || v == "update" || v == "patch" || v == "delete" || v == "deletecollection" || v == "*" {
			return true // only write-access is critical here.
		}
	}
	return false // list/get access for pod roles or clusterroles.
}

func (r Rule) isHarmless() bool {
	if len(r.Resources) == 2 &&
		slices.Contains(r.Resources, "selfsubjectaccessreviews") &&
		slices.Contains(r.Resources, "selfsubjectrulesreviews") {
		return true
	}
	if len(r.Resources) == 1 &&
		(slices.Contains(r.Resources, "selfsubjectreviews") ||
			slices.Contains(r.Resources, "clustertrustbundles")) {
		return true
	}
	return false
}

func (r Rule) isClusterScoped() bool {
	return r.Scope == "clusterrole"
}

func join(s []string) string {
	return strings.Join(s, "/")
}
