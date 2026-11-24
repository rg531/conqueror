// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"net/http"
	"time"
)

const BASE_URL = "http://169.254.169.254"

func GetProvider() (bool, string, string) {
	status, header, _ := httpGet(BASE_URL)

	if header.Get("Metadata-Flavor") == "Google" || header.Get("X-Goog-Metadatasever-Ready") != "" {
		return true, "GCP", BASE_URL
	}
	if header.Get("X-Ms-Metadata-Status") != "" {
		return true, "AZURE", BASE_URL
	}
	if header.Get("X-OpenStack-API-Version") != "" {
		return true, "OpenStack", BASE_URL
	}
	if header.Get("Server") == "EC2ws" {
		return true, "AWS", BASE_URL
	}
	if status == http.StatusOK {
		return true, "unknown cloud provider", BASE_URL
	}

	// no error check needed,
	// if we did not get those headers and status is not 200/OK,
	// we exclude the possibility of running in a cloud env.
	return false, "", BASE_URL
}

func IsReachableEndpoint(path string) bool {
	status, _, err := httpGet(BASE_URL + path)
	if err == nil && status == http.StatusOK {
		return true
	}
	return false

}
func httpGet(url string) (int, http.Header, error) {
	client := http.Client{
		Timeout: 500 * time.Millisecond,
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Metadata-Flavor", "Google") // GCP requirement
	req.Header.Set("Metadata", "true")          // Azure requirement
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header, nil
}
