// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// get all clusterrolebindings
func GetClusterRoleBindings() ([]rbacv1.ClusterRoleBinding, error) {
	// set timeout:
	ctx, cancel := DefaultCtx()
	defer cancel()
	// send request
	bindings, err := instance.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	} else {
		return bindings.Items, nil
	}
}

// get all clusterroles
func ListClusterRoles() ([]rbacv1.ClusterRole, error) {
	// set timeout:
	ctx, cancel := DefaultCtx()
	defer cancel()
	// send request
	clusterRoles, err := instance.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	} else {
		return clusterRoles.Items, nil
	}
}

// get a single clusterrole by binding name (clusterrolebinding.name)
func GetClusterRole(bindingName string) ([]rbacv1.PolicyRule, error) {
	// set timeout:
	ctx, cancel := DefaultCtx()
	defer cancel()
	// send request
	clusterRole, err := instance.clientset.RbacV1().ClusterRoles().Get(ctx, bindingName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	} else {
		return clusterRole.Rules, nil
	}
}
