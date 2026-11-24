// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	"log/slog"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func IsAllowedTo(verb string, resource string, namespace string, group string) bool {
	// prepare request:
	review := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      verb,
				Resource:  resource,
				Group:     group,
			},
		},
	}
	// set timeout:
	ctx, cancel := DefaultCtx()
	defer cancel()
	// send request:
	result, err := instance.clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		slog.Error("error checking RBAC", "verb", verb, "resource", resource, "reason", err)
		return false
	} else {
		slog.Debug("RBAC:", "verb", verb, "resource", resource, "namespace", namespace, "is_allowed", result.Status.Allowed)
		return result.Status.Allowed
	}
}

func GetRBAC(namespace string) (authorizationv1.SubjectRulesReviewStatus, error) {
	review := &authorizationv1.SelfSubjectRulesReview{
		Spec: authorizationv1.SelfSubjectRulesReviewSpec{
			Namespace: namespace,
		},
	}
	// set timeout:
	ctx, cancel := DefaultCtx()
	defer cancel()
	result, err := instance.clientset.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return authorizationv1.SubjectRulesReviewStatus{}, err
	} else {
		return result.Status, err
	}
}

func Whoami() string {
	// prepare request:
	review := &authenticationv1.SelfSubjectReview{}
	// set timeout:
	ctx, cancel := DefaultCtx()
	defer cancel()
	// send request:
	res, err := instance.clientset.AuthenticationV1().SelfSubjectReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		slog.Error("error getting service-account name", "error", err)
		return "unknown"
	}
	accountDetails := strings.Split(res.Status.UserInfo.Username, ":") // format is system:serviceaccount:[namespace]:[account-name]
	thisAccount := accountDetails[len(accountDetails)-1]
	return strings.ToLower(strings.TrimSpace(thisAccount))
}
