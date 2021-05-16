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

package main

import (
	"context"
	"flag"
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/klog"

	"github.com/cilium/cilium-sysdump/internal/defaults"
	"github.com/cilium/cilium-sysdump/pkg/sysdump"
)

func main() {
	fs := flag.NewFlagSet("", flag.ExitOnError)

	ciliumLabels := fs.String("cilium-labels", defaults.CiliumLabels, "the labels used to target Cilium pods")
	ciliumNamespace := fs.String("cilium-namespace", defaults.CiliumNamespace, "the namespace Cilium in running in")
	ciliumOperatorLabels := fs.String("cilium-operator-labels", defaults.CiliumOperatorLabels, "the labels used to target Cilium operator pods")
	ciliumOperatorNamespace := fs.String("cilium-operator-namespace", defaults.CiliumOperatorNamespace, "the namespace Cilium operator is running in")
	debug := fs.Bool("debug", defaults.Debug, "whether to enable debug logging")
	hubbleLabels := fs.String("hubble-labels", defaults.HubbleLabels, "the labels used to target Hubble pods")
	hubbleNamespace := fs.String("hubble-namespace", defaults.HubbleNamespace, "the namespace Hubble is running in")
	hubbleRelayLabels := fs.String("hubble-relay-labels", defaults.HubbleRelayLabels, "the labels used to target Hubble Relay pods")
	hubbleRelayNamespace := fs.String("hubble-relay-namespace", defaults.HubbleRelayNamespace, "the namespace Hubble Relay is running in")
	hubbleUiLabels := fs.String("hubble-ui-labels", defaults.HubbleUiLabels, "the labels used to target Hubble UI pods")
	hubbleUiNamespace := fs.String("hubble-ui-namespace", defaults.HubbleUiNamespace, "the namespace Hubble UI is running in")
	kubeconfig := fs.String("kubeconfig", defaults.Kubeconfig, "")
	logsLimitBytes := fs.Int64("logs-limit-bytes", defaults.LogsLimitBytes, "the limit on the number of bytes to use when collecting logs")
	logsSinceTime := fs.Duration("logs-since-time", defaults.LogsSinceTime, "how far back in time to go when collecting logs")
	nodeFilter := fs.String("node-list", defaults.NodeFilter, "comma-separated list of node ips or names to filter pods for which to collect gops and logs by")
	quick := fs.Bool("quick", defaults.Quick, "whether to enable quick mode (i.e. skip collection of cilium bugtool and logs)")
	outputFileName := fs.String("output-filename", defaults.OutputFileName, "the name of the resulting file (without extension)\n'<ts>' can be used as the placeholder for the timestamp")

	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatalf("failed to parse command-line flags: %v", err)
	}

	// Enable debug logging if requested to.
	l := log.WithContext(context.Background())
	if *debug {
		l.Logger.SetLevel(log.DebugLevel)
	}
	klog.SetOutput(io.Discard)

	// Create a context.
	ctx, fn := context.WithCancel(context.Background())
	defer fn()

	// Collect the sysdump.
	s, err := sysdump.NewSysdump(sysdump.SysdumpOptions{
		CiliumLabelSelector:         *ciliumLabels,
		CiliumNamespace:             *ciliumNamespace,
		CiliumOperatorLabelSelector: *ciliumOperatorLabels,
		CiliumOperatorNamespace:     *ciliumOperatorNamespace,
		HubbleLabelSelector:         *hubbleLabels,
		HubbleNamespace:             *hubbleNamespace,
		HubbleRelayLabelSelector:    *hubbleRelayLabels,
		HubbleRelayNamespace:        *hubbleRelayNamespace,
		HubbleUiLabelSelector:       *hubbleUiLabels,
		HubbleUiNamespace:           *hubbleUiNamespace,
		LargeSysdumpAbortTimeout:    defaults.LargeSysdumpAbortTimeout,
		LargeSysdumpThreshold:       defaults.LargeSysdumpThreshold,
		Logger:                      l,
		LogsLimitBytes:              *logsLimitBytes,
		LogsSinceTime:               *logsSinceTime,
		NodeFilter:                  *nodeFilter,
		OutputFileName:              *outputFileName,
		Quick:                       *quick,
		RESTClientGetter: &genericclioptions.ConfigFlags{
			KubeConfig: kubeconfig,
		},
	})
	if err != nil {
		log.Fatalf("failed to collect sysdump: %v", err)
	}
	if err := s.Collect(ctx); err != nil {
		log.Fatalf("failed to collect sysdump: %v", err)
	}
}
