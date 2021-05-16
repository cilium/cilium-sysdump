// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sysdump

import (
	"regexp"
)

const (
	ciliumAgentContainerName     = "cilium-agent"
	ciliumConfigConfigMapName    = "cilium-config"
	ciliumDaemonSetName          = "cilium"
	ciliumEtcdSecretsSecretName  = "cilium-etcd-secrets"
	ciliumOperatorDeploymentName = "cilium-operator"
	hubbleContainerName          = "hubble"
	hubbleDaemonSetName          = "hubble"
	hubbleRelayContainerName     = "hubble-relay"
	hubbleRelayDeploymentName    = "hubble-relay"
	hubbleUiDeploymentName       = "hubble-ui"
	redacted                     = "XXXXXX"
)

const (
	ciliumBugtoolFileName                    = "cilium-bugtool-%s-<ts>.tar"
	ciliumClusterWideNetworkPoliciesFileName = "ccnp-<ts>.yaml"
	ciliumConfigMapFileName                  = "cilium-cm-<ts>.yaml"
	ciliumDaemonSetFileName                  = "cilium-ds-<ts>.yaml"
	ciliumEndpointsFileName                  = "cep-<ts>.yaml"
	ciliumEtcdSecretFileName                 = "cilium-etcd-secrets-<ts>.yaml"
	ciliumIdentitiesFileName                 = "ciliumid-<ts>.yaml"
	ciliumLogsFileName                       = "%s-%s-<ts>.log"
	ciliumPreviousLogsFileName               = "%s-%s-<ts>-prev.log"
	ciliumNetworkPoliciesFileName            = "cnp-<ts>.yaml"
	ciliumNodesFileName                      = "cn-<ts>.yaml"
	ciliumOperatorDeploymentFileName         = "cilium-operator-deploy-<ts>.yaml"
	gopsFileName                             = "%s-%s-<ts>-%s.txt"
	hubbleDaemonsetFileName                  = "hubble-ds-<ts>.yaml"
	hubbleRelayDeploymentFileName            = "hubble-relay-deploy-<ts>.yaml"
	hubbleUiDeploymentFileName               = "hubble-ui-deploy-<ts>.yaml"
	kubernetesEventsFileName                 = "k8s-ev-<ts>.yaml"
	kubernetesNamespacesFileName             = "k8s-ns-<ts>.yaml"
	kubernetesNetworkPoliciesFileName        = "netpol-<ts>.yaml"
	kubernetesNodesFileName                  = "k8s-no-<ts>.yaml"
	kubernetesPodsFileName                   = "po-<ts>.yaml"
	kubernetesPodsSummaryFileName            = "po-<ts>.txt"
	kubernetesServicesFileName               = "svc-<ts>.yaml"
	kubernetesVersionInfoFileName            = "k8s-version-info-<ts>.txt"
	timestampPlaceholderFileName             = "<ts>"
)

const (
	dirMode    = 0700
	fileMode   = 0600
	timeFormat = "20060102-150405"
)

var (
	ciliumBugtoolFileNameRegex = regexp.MustCompile("ARCHIVE at (.*)\n")
	ciliumBugtoolCommand       = "cilium-bugtool"
	gopsCommand                = "/bin/gops"
	gopsPID                    = "1"
	gopsStats                  = []string{
		"memstats",
		"stack",
		"stats",
	}
)
