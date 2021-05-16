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

package defaults

import (
	"path/filepath"
	"time"

	"k8s.io/client-go/util/homedir"
)

const (
	labelPrefix = "k8s-app="
)

const (
	CiliumLabels             = labelPrefix + "cilium"
	CiliumNamespace          = "kube-system"
	CiliumOperatorLabels     = "io.cilium/app=operator"
	CiliumOperatorNamespace  = CiliumNamespace
	Debug                    = false
	HubbleLabels             = labelPrefix + "hubble"
	HubbleNamespace          = CiliumNamespace
	HubbleRelayLabels        = labelPrefix + "hubble-relay"
	HubbleRelayNamespace     = CiliumNamespace
	HubbleUiLabels           = labelPrefix + "hubble-ui"
	HubbleUiNamespace        = CiliumNamespace
	LargeSysdumpAbortTimeout = 5 * time.Second
	LargeSysdumpThreshold    = 20
	LogsSinceTime            = 8760 * time.Hour // 1y
	LogsLimitBytes           = 1073741824       // 1GiB
	NodeFilter               = ""
	Quick                    = false
	OutputFileName           = "cilium-sysdump-<ts>" // "<ts>" will be replaced with the timestamp
)

var (
	Kubeconfig = filepath.Join(homedir.HomeDir(), ".kube", "config")
)
