// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	"slices"

	rbacv1 "k8s.io/api/rbac/v1"
)

//
// encapsulates a pods state within a scan.
//

type Pod struct {
	Namespace      string
	ServiceAccount string
	ClusterRules   []Rule
	NamespaceRules []Rule
}

// check the pods rules if he is allowed to use verb/resource:
func (p Pod) HasClusterRuleFor(verb, resource string) bool {
	return slices.ContainsFunc(p.ClusterRules, func(r Rule) bool {
		return r.Allows(verb, resource)
	})
}
func (p Pod) HasNamespaceRuleFor(verb, resource string) bool {
	return slices.ContainsFunc(p.NamespaceRules, func(r Rule) bool {
		return r.Allows(verb, resource)
	})
}

func (p Pod) HasSubject(subject rbacv1.Subject) bool {
	return subject.Name == p.ServiceAccount &&
		subject.Namespace == p.Namespace &&
		subject.Kind == rbacv1.ServiceAccountKind
}
