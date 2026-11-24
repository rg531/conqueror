// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	"context"
	"fmt"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var instance *KubernetesClient

type KubernetesClient struct {
	clientset *kubernetes.Clientset
}

func Init() error {
	client, err := GetKubernetesClient()
	if err != nil {
		return err
	} else {
		instance = client
		return nil
	}
}

func GetKubernetesClient() (*KubernetesClient, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("error creating config for kubernetes-client: %w", err)
	}
	config.QPS = 50    // allow 50 requests in parallel.
	config.Burst = 100 // allow spikes of 100 requests in parallel.
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating clientset for kubernetes-client: %w", err)
	}
	return &KubernetesClient{clientset: clientset}, nil
}

// set a default timeout for all API calls:
func DefaultCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 500*time.Millisecond)
}
