// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func GetSecrets(namespace string) ([]corev1.Secret, error) {
	// set timeout:
	ctx, cancel := DefaultCtx()
	defer cancel()
	// send request:
	secretsList, err := instance.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	} else {
		return secretsList.Items, nil
	}
}
