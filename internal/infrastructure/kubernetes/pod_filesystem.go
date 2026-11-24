// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	"os"
)

const NAMESPACE_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
const TOKEN_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/token"

func HasK8sToken() (string, bool) {
	tokenBytes, err := os.ReadFile(TOKEN_FILE)
	token := string(tokenBytes)
	if err != nil {
		return "did not find " + TOKEN_FILE, false
	} else {
		if len(token) <= 16 {
			if len(token) <= 4 {
				return "*********", true
			}
			return "*********" + token[len(token)-2:], true
		}
		return token[0:10] + "*********" + token[len(token)-6:], true
	}
}

func HasK8sNamespace() (string, bool) {
	namespace, err := os.ReadFile(NAMESPACE_FILE)
	if err != nil {
		return "did not find " + NAMESPACE_FILE, false
	} else {
		return string(namespace), true
	}
}
