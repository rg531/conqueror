// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	"log/slog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func GetNamespaces() []string {
	// set timeout:
	ctx, cancel := DefaultCtx()
	defer cancel()
	// send request:
	namespaceList, err := instance.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		slog.Error("failed to list namespaces:", "error", err)
		return nil
	} else {
		// convert NamespaceList to string[]:
		namespaces := make([]string, len(namespaceList.Items))
		for i, item := range namespaceList.Items {
			namespaces[i] = item.Name
		}
		return namespaces
	}
}
