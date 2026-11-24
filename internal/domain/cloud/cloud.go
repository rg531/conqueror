// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"conqueror/internal/domain/events"
	"conqueror/internal/infrastructure/cloud"
)

var IMDSEndpoints = []string{
	// AWS
	"/latest/meta-data/",
	"/latest/meta-data/iam/security-credentials/",
	"/latest/user-data",
	"/latest/meta-data/public-keys/0/openssh-key",
	"/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",

	// GCP
	"/computeMetadata/v1/instance/service-accounts/",
	"/computeMetadata/v1/instance/service-accounts/default/token",
	"/computeMetadata/v1/instance/service-accounts/default/scopes",
	"/computeMetadata/v1/instance/attributes/kube-env",
	"/computeMetadata/v1/instance/attributes/user-data",

	// Azure
	"/metadata/instance?api-version=2021-02-01",
	"/metadata/instance/compute/userData?api-version=2021-02-01&format=text",
	"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://azure.com",

	// OpenStack
	"/openstack/latest/meta_data.json",
	"/openstack/latest/user_data",

	// DigitalOcean
	"/metadata/v1.json",
}

func IsRunningInCloud() bool {
	inCloud, provider, url := cloud.GetProvider()
	if inCloud {
		events.HandleMetaInfo("environment", "cloud")
		events.HandleMetaInfo("cloud_provider", provider)
		events.HandleVulnerability(events.Cloud, "cloud provider found", "cloud_provider_found", provider+" at "+url)
	} else {
		events.HandleInfo("no cloud provider found", "could not reach "+url)
	}
	return inCloud
}

func CheckIMDSEndpoints() {
	for _, endpoint := range IMDSEndpoints {
		isReachable := cloud.IsReachableEndpoint(endpoint)
		if isReachable {
			events.HandleVulnerability(events.Cloud, "found IMDS endpoint", "found_cloud_imds_endpoint", cloud.BASE_URL+"endpoint")
		}
	}
}
