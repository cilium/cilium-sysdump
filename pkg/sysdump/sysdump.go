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
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	archiver "github.com/mholt/archiver/v3"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/cilium/cilium-sysdump/internal/defaults"
	"github.com/cilium/cilium-sysdump/internal/k8s"
	stringutils "github.com/cilium/cilium-sysdump/internal/utils/strings"
)

type SysdumpOptions struct {
	CiliumLabelSelector         string
	CiliumNamespace             string
	CiliumOperatorLabelSelector string
	CiliumOperatorNamespace     string
	HubbleLabelSelector         string
	HubbleNamespace             string
	HubbleRelayLabelSelector    string
	HubbleRelayNamespace        string
	HubbleUiLabelSelector       string
	HubbleUiNamespace           string
	LargeSysdumpAbortTimeout    time.Duration
	LargeSysdumpThreshold       int32
	Logger                      *log.Entry
	LogsLimitBytes              int64
	LogsSinceTime               time.Duration
	NodeFilter                  string
	OutputFileName              string
	Quick                       bool
	RESTClientGetter            genericclioptions.RESTClientGetter
}

type Sysdump interface {
	Collect(context.Context) error
}

type sysdump struct {
	k k8s.Client
	o SysdumpOptions
}

type sysdumpTask func() error

func NewSysdump(o SysdumpOptions) (Sysdump, error) {
	k, err := k8s.NewClient(o.RESTClientGetter)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}
	return &sysdump{
		k: k,
		o: o,
	}, nil
}

func (c *sysdump) Collect(ctx context.Context) error {
	// Grab the current timestamp and create a temporary directory to hold the files.
	t := time.Now()

	// replaceTimestamp can be used to replace the special timestamp placeholder in file and directory names.
	replaceTimestamp := func(f string) string {
		return strings.Replace(f, timestampPlaceholderFileName, t.Format(timeFormat), -1)
	}

	d, err := ioutil.TempDir("", "*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	d = filepath.Join(d, replaceTimestamp(c.o.OutputFileName))
	if err := os.MkdirAll(d, dirMode); err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	c.o.Logger.Debugf("Using %v as a temporary directory", d)

	// absoluteTempPath returns the absolute path where to store the specified filename temporarily.
	absoluteTempPath := func(f string) string {
		return path.Join(d, replaceTimestamp(f))
	}

	// Grab the Kubernetes nodes for the target cluster.
	c.o.Logger.Info("Collecting Kubernetes nodes")
	n, err := c.k.GetNodes(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect Kubernetes nodes: %w", err)
	}
	c.o.Logger.Debug("Finished collecting Kubernetes nodes")

	// Exit if there are no nodes, as there's nothing to do.
	if len(n.Items) == 0 {
		c.o.Logger.Infof("No nodes found in the current cluster")
		return nil
	}
	// If there are many nodes and no filters are specified, issue a warning and wait for a while before proceeding so the user can cancel the process.
	if len(n.Items) > int(c.o.LargeSysdumpThreshold) && (c.o.NodeFilter == defaults.NodeFilter && c.o.LogsLimitBytes == defaults.LogsLimitBytes && c.o.LogsSinceTime == defaults.LogsSinceTime) {
		c.o.Logger.Warnf("Detected a large cluster (%d nodes)", len(n.Items))
		c.o.Logger.Warnf("Consider using a node filter, a custom log size limit and/or a custom log time range to decrease the size of the sysdump")
		c.o.Logger.Warnf("Waiting for %s before continuing", c.o.LargeSysdumpAbortTimeout)
		t := time.NewTicker(c.o.LargeSysdumpAbortTimeout)
		defer t.Stop()
	wait:
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-t.C:
				break wait
			}
		}
	}

	// Build the list of node names in which the user is interested.
	l, err := buildNodeNameList(n, c.o.NodeFilter)
	if err != nil {
		return fmt.Errorf("failed to build node list: %w", err)
	}
	nodeList := l
	c.o.Logger.Debugf("Restricting bugtool and logs collection to pods in %v", nodeList)

	// tasks is the list of base tasks to be run.
	tasks := []sysdumpTask{
		// Get Kubernetes nodes.
		func() error {
			defer c.o.Logger.Debug("Finished collecting Kubernetes nodes")
			if err := writeYaml(absoluteTempPath(kubernetesNodesFileName), n); err != nil {
				return fmt.Errorf("failed to collect Kubernetes nodes: %w", err)
			}
			return nil
		},
		// Get Kubernetes version.
		func() error {
			c.o.Logger.Info("Collecting Kubernetes version")
			defer c.o.Logger.Debug("Finished collecting Kubernetes version")
			v, err := c.k.GetVersion(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect Kubernetes version: %w", err)
			}
			if err := writeString(absoluteTempPath(kubernetesVersionInfoFileName), v); err != nil {
				return fmt.Errorf("failed to dump Kubernetes version: %w", err)
			}
			return nil
		},
		// Get Kubernetes events.
		func() error {
			c.o.Logger.Info("Collecting Kubernetes events")
			defer c.o.Logger.Debug("Finished collecting Kubernetes events")
			v, err := c.k.GetEvents(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect Kubernetes events: %w", err)
			}
			if err := writeYaml(absoluteTempPath(kubernetesEventsFileName), v); err != nil {
				return fmt.Errorf("failed to collect Kubernetes events: %w", err)
			}
			return nil
		},
		// Get Kubernetes namespaces.
		func() error {
			c.o.Logger.Info("Collecting Kubernetes namespaces")
			defer c.o.Logger.Debug("Finished collecting Kubernetes namespaces")
			v, err := c.k.GetNamespaces(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect Kubernetes namespaces: %w", err)
			}
			if err := writeYaml(absoluteTempPath(kubernetesNamespacesFileName), v); err != nil {
				return fmt.Errorf("failed to collect Kubernetes namespaces: %w", err)
			}
			return nil
		},
		// Get Kubernetes pods.
		func() error {
			c.o.Logger.Info("Collecting Kubernetes pods")
			defer c.o.Logger.Debug("Finished collecting Kubernetes pods")
			v, err := c.k.GetPods(ctx, corev1.NamespaceAll, "")
			if err != nil {
				return fmt.Errorf("failed to collect Kubernetes pods: %w", err)
			}
			if err := writeYaml(absoluteTempPath(kubernetesPodsFileName), v); err != nil {
				return fmt.Errorf("failed to collect Kubernetes pods: %w", err)
			}
			return nil
		},
		// Get Kubernetes pods summary.
		func() error {
			c.o.Logger.Info("Collecting Kubernetes pods summary")
			defer c.o.Logger.Debug("Finished collecting Kubernetes pods summary")
			v, err := c.k.GetPodsTable(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect Kubernetes pods summary: %w", err)
			}
			if err := writeTable(absoluteTempPath(kubernetesPodsSummaryFileName), v); err != nil {
				return fmt.Errorf("failed to collect Kubernetes pods summary: %w", err)
			}
			return nil
		},
		// Get Kubernetes services.
		func() error {
			c.o.Logger.Info("Collecting Kubernetes services")
			defer c.o.Logger.Debug("Finished collecting Kubernetes services")
			v, err := c.k.GetServices(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect Kubernetes services: %w", err)
			}
			if err := writeYaml(absoluteTempPath(kubernetesServicesFileName), v); err != nil {
				return fmt.Errorf("failed to collect Kubernetes services: %w", err)
			}
			return nil
		},
		// Get Kubernetes network policies.
		func() error {
			c.o.Logger.Info("Collecting Kubernetes network policies")
			defer c.o.Logger.Debug("Finished collecting Kubernetes network policies")
			v, err := c.k.GetNetworkPolicies(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect Kubernetes network policies: %w", err)
			}
			if err := writeYaml(absoluteTempPath(kubernetesNetworkPoliciesFileName), v); err != nil {
				return fmt.Errorf("failed to collect Kubernetes network policies: %w", err)
			}
			return nil
		},
		// Get Cilium network policies.
		func() error {
			c.o.Logger.Info("Collecting Cilium network policies")
			defer c.o.Logger.Debug("Finished collecting Cilium network policies")
			v, err := c.k.GetCiliumNetworkPolicies(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect Cilium network policies: %w", err)
			}
			if err := writeYaml(absoluteTempPath(ciliumNetworkPoliciesFileName), v); err != nil {
				return fmt.Errorf("failed to collect Cilium network policies: %w", err)
			}
			return nil
		},
		// Get Cilium cluster-wide network policies.
		func() error {
			c.o.Logger.Info("Collecting Cilium cluster-wide network policies")
			defer c.o.Logger.Debug("Finished collecting Cilium cluster-wide network policies")
			v, err := c.k.GetCiliumClusterWideNetworkPolicies(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect Cilium cluster-wide network policies: %w", err)
			}
			if err := writeYaml(absoluteTempPath(ciliumClusterWideNetworkPoliciesFileName), v); err != nil {
				return fmt.Errorf("failed to collect Cilium cluster-wide network policies: %w", err)
			}
			return nil
		},
		// Get Cilium endpoints.
		func() error {
			c.o.Logger.Info("Collecting Cilium endpoints")
			defer c.o.Logger.Debug("Finished collecting Cilium endpoints")
			v, err := c.k.GetCiliumEndpoints(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect Cilium endpoints: %w", err)
			}
			if err := writeYaml(absoluteTempPath(ciliumEndpointsFileName), v); err != nil {
				return fmt.Errorf("failed to collect Cilium endpoints: %w", err)
			}
			return nil
		},
		// Get Cilium identities.
		func() error {
			c.o.Logger.Info("Collecting Cilium identities")
			defer c.o.Logger.Debug("Finished collecting Cilium identities")
			v, err := c.k.GetCiliumIdentities(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect Cilium identities: %w", err)
			}
			if err := writeYaml(absoluteTempPath(ciliumIdentitiesFileName), v); err != nil {
				return fmt.Errorf("failed to collect Cilium identities: %w", err)
			}
			return nil
		},
		// Get Cilium nodes.
		func() error {
			c.o.Logger.Info("Collecting Cilium nodes")
			defer c.o.Logger.Debug("Finished collecting Cilium nodes")
			v, err := c.k.GetCiliumNodes(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect Cilium nodes: %w", err)
			}
			if err := writeYaml(absoluteTempPath(ciliumNodesFileName), v); err != nil {
				return fmt.Errorf("failed to collect Cilium nodes: %w", err)
			}
			return nil
		},
		// Get the Cilium etcd secret (if it exists).
		func() error {
			c.o.Logger.Info("Collecting Cilium etcd secret")
			defer c.o.Logger.Debug("Finished collecting Cilium etcd secret")
			v, err := c.k.GetSecret(ctx, c.o.CiliumNamespace, ciliumEtcdSecretsSecretName)
			if err != nil {
				if errors.IsNotFound(err) {
					c.o.Logger.Warnf("secret %q not found in namespace %q - this is expected when using the CRD KVStore", ciliumEtcdSecretsSecretName, c.o.CiliumNamespace)
					return nil
				}
				return fmt.Errorf("failed to collect Cilium etcd secret: %w", err)
			}
			// Redact the actual values.
			for k := range v.Data {
				v.Data[k] = []byte(redacted)
			}
			if err := writeYaml(absoluteTempPath(ciliumEtcdSecretFileName), v); err != nil {
				return fmt.Errorf("failed to collect Cilium etcd secret: %w", err)
			}
			return nil
		},
		// Get the Cilium configuration.
		func() error {
			c.o.Logger.Info("Collecting the Cilium configuration")
			defer c.o.Logger.Debug("Finished collecting Cilium configuration")
			v, err := c.k.GetConfigMap(ctx, c.o.CiliumNamespace, ciliumConfigConfigMapName)
			if err != nil {
				return fmt.Errorf("failed to collect the Cilium configuration: %w", err)
			}
			if err := writeYaml(absoluteTempPath(ciliumConfigMapFileName), v); err != nil {
				return fmt.Errorf("failed to collect the Cilium configuration: %w", err)
			}
			return nil
		},
		// Get the Cilium daemonset.
		func() error {
			c.o.Logger.Info("Collecting the Cilium daemonset")
			defer c.o.Logger.Debug("Finished collecting Cilium daemonset")
			v, err := c.k.GetDaemonSet(ctx, c.o.CiliumNamespace, ciliumDaemonSetName)
			if err != nil {
				return fmt.Errorf("failed to collect the Cilium daemonset: %w", err)
			}
			if err := writeYaml(absoluteTempPath(ciliumDaemonSetFileName), v); err != nil {
				return fmt.Errorf("failed to collect the Cilium daemonset: %w", err)
			}
			return nil
		},
		// Get the Hubble daemonset.
		func() error {
			c.o.Logger.Info("Collecting the Hubble daemonset")
			defer c.o.Logger.Debug("Finished collecting the Hubble daemonset")
			v, err := c.k.GetDeployment(ctx, c.o.HubbleNamespace, hubbleDaemonSetName)
			if err != nil {
				if errors.IsNotFound(err) {
					c.o.Logger.Warnf("daemonset %q not found in namespace %q - this is expected in recent versions of Cilium", hubbleDaemonSetName, c.o.HubbleNamespace)
					return nil
				}
				return fmt.Errorf("failed to collect the Hubble daemonset: %w", err)
			}
			if err := writeYaml(absoluteTempPath(hubbleDaemonsetFileName), v); err != nil {
				return fmt.Errorf("failed to collect the Hubble daemonset: %w", err)
			}
			return nil
		},
		// Get the Hubble Relay deployment.
		func() error {
			c.o.Logger.Info("Collecting the Hubble Relay deployment")
			defer c.o.Logger.Debug("Finished collecting the Hubble Relay deployment")
			v, err := c.k.GetDeployment(ctx, c.o.HubbleRelayNamespace, hubbleRelayDeploymentName)
			if err != nil {
				if errors.IsNotFound(err) {
					c.o.Logger.Warnf("deployment %q not found in namespace %q", hubbleRelayDeploymentName, c.o.HubbleRelayNamespace)
					return nil
				}
				return fmt.Errorf("failed to collect the Hubble Relay deployment: %w", err)
			}
			if err := writeYaml(absoluteTempPath(hubbleRelayDeploymentFileName), v); err != nil {
				return fmt.Errorf("failed to collect the Hubble Relay deployment: %w", err)
			}
			return nil
		},
		// Get the Hubble UI deployment.
		func() error {
			c.o.Logger.Info("Collecting the Hubble UI deployment")
			defer c.o.Logger.Debug("Finished collecting the Hubble UI deployment")
			v, err := c.k.GetDeployment(ctx, c.o.HubbleUiNamespace, hubbleUiDeploymentName)
			if err != nil {
				if errors.IsNotFound(err) {
					c.o.Logger.Warnf("deployment %q not found in namespace %q", hubbleUiDeploymentName, c.o.HubbleUiNamespace)
					return nil
				}
				return fmt.Errorf("failed to collect the Hubble UI deployment: %w", err)
			}
			if err := writeYaml(absoluteTempPath(hubbleUiDeploymentFileName), v); err != nil {
				return fmt.Errorf("failed to collect the Hubble UI deployment: %w", err)
			}
			return nil
		},
		// Get the Cilium operator deployment.
		func() error {
			c.o.Logger.Info("Collecting the Cilium operator deployment")
			defer c.o.Logger.Debug("Finished collecting the Cilium operator deployment")
			v, err := c.k.GetDeployment(ctx, c.o.CiliumNamespace, ciliumOperatorDeploymentName)
			if err != nil {
				return fmt.Errorf("failed to collect the Cilium operator deployment: %w", err)
			}
			if err := writeYaml(absoluteTempPath(ciliumOperatorDeploymentFileName), v); err != nil {
				return fmt.Errorf("failed to collect the Cilium operator deployment: %w", err)
			}
			return nil
		},
		// Get the gops stats from Cilium pods.
		func() error {
			c.o.Logger.Info("Collecting gops stats from Cilium pods")
			defer c.o.Logger.Debug("Finished collecting gops stats from Cilium pods")
			p, err := c.k.GetPods(ctx, c.o.CiliumNamespace, c.o.CiliumLabelSelector)
			if err != nil {
				return fmt.Errorf("failed to get Cilium pods: %w", err)
			}
			if err := c.collectGops(ctx, c.o.Logger, filterPods(p, nodeList), ciliumAgentContainerName, absoluteTempPath); err != nil {
				return fmt.Errorf("failed to collect Cilium gops: %w", err)
			}
			return nil
		},
		// Get the gops stats from Hubble pods.
		func() error {
			c.o.Logger.Info("Collecting gops stats from Hubble pods")
			defer c.o.Logger.Debug("Finished collecting gops stats from Hubble pods")
			p, err := c.k.GetPods(ctx, c.o.HubbleNamespace, c.o.HubbleLabelSelector)
			if err != nil {
				return fmt.Errorf("failed to get Hubble pods: %w", err)
			}
			if err := c.collectGops(ctx, c.o.Logger, filterPods(p, nodeList), hubbleContainerName, absoluteTempPath); err != nil {
				return fmt.Errorf("failed to collect Hubble gops: %w", err)
			}
			return nil
		},
		// Get the gops stats from Hubble Relay pods.
		func() error {
			c.o.Logger.Info("Collecting gops stats from Hubble Relay pods")
			defer c.o.Logger.Debug("Finished collecting gops stats from Hubble Relay pods")
			p, err := c.k.GetPods(ctx, c.o.HubbleNamespace, c.o.HubbleRelayLabelSelector)
			if err != nil {
				return fmt.Errorf("failed to get Hubble Relay pods: %w", err)
			}
			if err := c.collectGops(ctx, c.o.Logger, filterPods(p, nodeList), hubbleRelayContainerName, absoluteTempPath); err != nil {
				return fmt.Errorf("failed to collect Hubble Relay gops: %w", err)
			}
			return nil
		},
	}

	// If we're not running in quick mode, additionally collect 'cilium-bugtool' and logs.
	if !c.o.Quick {
		sinceTime := t.Add(-c.o.LogsSinceTime)
		tasks = append(tasks, []sysdumpTask{
			// Get the output of 'cilium-bugtool' from Cilium pods.
			func() error {
				c.o.Logger.Info("Collecting 'cilium-bugtool' output from Cilium pods")
				defer c.o.Logger.Debug("Finished collecting 'cilium-bugtool' output from Cilium pods")
				p, err := c.k.GetPods(ctx, c.o.CiliumNamespace, c.o.CiliumLabelSelector)
				if err != nil {
					return fmt.Errorf("failed to get Cilium pods: %w", err)
				}
				if err := c.collectBugtool(ctx, c.o.Logger, filterPods(p, nodeList), ciliumAgentContainerName, absoluteTempPath); err != nil {
					return fmt.Errorf("failed to collect 'cilium-bugtool': %w", err)
				}
				return nil
			},
			// Get logs from Cilium.
			func() error {
				c.o.Logger.Info("Collecting logs from Cilium pods")
				defer c.o.Logger.Debug("Finished collecting logs from Cilium pods")
				p, err := c.k.GetPods(ctx, c.o.CiliumNamespace, c.o.CiliumLabelSelector)
				if err != nil {
					return fmt.Errorf("failed to get logs from Cilium pods")
				}
				if err := c.collectLogs(ctx, c.o.Logger, filterPods(p, nodeList), sinceTime, c.o.LogsLimitBytes, absoluteTempPath); err != nil {
					return fmt.Errorf("failed to collect logs from Cilium pods")
				}
				return nil
			},
			// Get logs from the Cilium operator.
			func() error {
				c.o.Logger.Info("Collecting logs from Cilium operator pods")
				defer c.o.Logger.Debug("Finished collecting logs from Cilium operator pods")
				p, err := c.k.GetPods(ctx, c.o.CiliumOperatorNamespace, c.o.CiliumOperatorLabelSelector)
				if err != nil {
					return fmt.Errorf("failed to get logs from Cilium operator pods")
				}
				if err := c.collectLogs(ctx, c.o.Logger, filterPods(p, nodeList), sinceTime, c.o.LogsLimitBytes, absoluteTempPath); err != nil {
					return fmt.Errorf("failed to collect logs from Cilium operator pods")
				}
				return nil
			},
			// Get logs from Hubble.
			func() error {
				c.o.Logger.Info("Collecting logs from Hubble pods")
				defer c.o.Logger.Debug("Finished collecting logs from Hubble pods")
				p, err := c.k.GetPods(ctx, c.o.HubbleNamespace, c.o.HubbleLabelSelector)
				if err != nil {
					return fmt.Errorf("failed to get logs from Hubble pods")
				}
				if err := c.collectLogs(ctx, c.o.Logger, filterPods(p, nodeList), sinceTime, c.o.LogsLimitBytes, absoluteTempPath); err != nil {
					return fmt.Errorf("failed to collect logs from Hubble pods")
				}
				return nil
			},
			// Get logs from Hubble Relay.
			func() error {
				c.o.Logger.Info("Collecting logs from Hubble Relay pods")
				defer c.o.Logger.Debug("Finished collecting logs from Hubble Relay pods")
				p, err := c.k.GetPods(ctx, c.o.HubbleRelayNamespace, c.o.HubbleRelayLabelSelector)
				if err != nil {
					return fmt.Errorf("failed to get logs from Hubble Relay pods")
				}
				if err := c.collectLogs(ctx, c.o.Logger, filterPods(p, nodeList), sinceTime, c.o.LogsLimitBytes, absoluteTempPath); err != nil {
					return fmt.Errorf("failed to collect logs from Hubble Relay pods")
				}
				return nil
			},
			// Get logs from Hubble UI.
			func() error {
				c.o.Logger.Info("Collecting logs from Hubble UI pods")
				defer c.o.Logger.Debug("Finished collecting logs from Hubble UI pods")
				p, err := c.k.GetPods(ctx, c.o.HubbleNamespace, c.o.HubbleLabelSelector)
				if err != nil {
					return fmt.Errorf("failed to get logs from Hubble UI pods")
				}
				if err := c.collectLogs(ctx, c.o.Logger, filterPods(p, nodeList), sinceTime, c.o.LogsLimitBytes, absoluteTempPath); err != nil {
					return fmt.Errorf("failed to collect logs from Hubble UI pods")
				}
				return nil
			},
		}...)
	}

	// Run the tasks.
	errCh := make(chan error)
	wgdCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(len(tasks))
	for _, f := range tasks {
		go func(f func() error) {
			defer wg.Done()
			if err := f(); err != nil {
				errCh <- err
			}
		}(f)
	}
	go func() {
		wg.Wait()
		close(wgdCh)
	}()

	// Wait for the tasks to finish.
	var merr error
loop:
	for {
		select {
		case <-wgdCh:
			break loop
		case err := <-errCh:
			merr = multierror.Append(merr, err)
		}
	}

	// Check if any errors occurred and warn the user.
	if merr != nil {
		c.o.Logger.Warnf("The sysdump may be incomplete — %s", merr.Error())
		c.o.Logger.Warnf("Please note that depending on your Cilium version and installation options, this may be expected")
	}

	// Create the zip file in the current directory.
	c.o.Logger.Info("Compiling sysdump")
	p, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}
	f := filepath.Join(p, replaceTimestamp(c.o.OutputFileName)+".zip")
	if err := archiver.Archive([]string{d}, f); err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	c.o.Logger.Infof("The sysdump has been saved to %s", f)

	// Try to remove the temporary directory.
	c.o.Logger.Debugf("Removing the temporary directory %s", d)
	if err := os.RemoveAll(d); err != nil {
		c.o.Logger.Warnf("failed to remove temporary directory %s: %v", d, err)
	}
	return nil
}

func buildNodeNameList(n *corev1.NodeList, filter string) ([]string, error) {
	w := strings.Split(strings.TrimSpace(filter), ",")
	r := make([]string, 0)
loop:
	// Iterate nodes and try to match either names or IPs to any of the specified filter strings.
	for _, n := range n.Items {
		n := n
		if len(w) == 0 || w[0] == "" {
			r = append(r, n.Name)
			continue loop
		}
		for _, f := range w {
			f := f
			if n.Name == f {
				r = append(r, n.Name)
				continue loop
			}
			for _, i := range n.Status.Addresses {
				if i.Address == f {
					r = append(r, n.Name)
					continue loop
				}
			}
		}
	}
	return r, nil
}

func (c *sysdump) collectBugtool(ctx context.Context, l *log.Entry, pods []*corev1.Pod, containerName string, path func(string) string) error {
	errCh := make(chan error)
	wgdCh := make(chan struct{})
	var wg sync.WaitGroup
	for _, p := range pods {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Run 'cilium-bugtool' in the pod.
			_, e, err := c.k.Exec(ctx, p.Namespace, p.Name, containerName, ciliumBugtoolCommand)
			if err != nil {
				errCh <- fmt.Errorf("failed to collect 'cilium-bugtool' output for %q in namespace %q: %w", p.Name, p.Namespace, err)
				return
			}
			// Capture the path to the resulting archive.
			m := ciliumBugtoolFileNameRegex.FindStringSubmatch(string(e))
			if len(m) != 2 || len(m[1]) == 0 {
				errCh <- fmt.Errorf("failed to collect 'cilium-bugtool' output for %q in namespace %q: output doesn't contain archive name", p.Name, p.Namespace)
				return
			}
			// Grab the resulting archive's contents from the pod.
			b, err := c.k.GetFileContents(ctx, p.Namespace, p.Name, containerName, m[1])
			if err != nil {
				errCh <- fmt.Errorf("failed to collect 'cilium-bugtool' output for %q: %w", p.Name, err)
				return
			}
			// Dump the resulting file's contents to the temporary directory.
			f := path(fmt.Sprintf(ciliumBugtoolFileName, p.Name))
			if err := writeBytes(f, b); err != nil {
				errCh <- fmt.Errorf("failed to collect 'cilium-bugtool' output for %q: %w", p.Name, err)
				return
			}
			// Untar the resulting file.
			t := archiver.Tar{
				StripComponents: 1,
			}
			if err := t.Unarchive(f, strings.Replace(f, ".tar", "", -1)); err != nil {
				l.Warnf("failed to unarchive 'cilium-bugtool' output for %q: %v", p.Name, err)
				return
			}
			// Remove the file we've copied from the pod.
			if err := os.Remove(f); err != nil {
				l.Warnf("failed to remove original 'cilium-bugtool' file: %v", err)
				return
			}
		}()
	}
	go func() {
		wg.Wait()
		close(wgdCh)
	}()

	var merr error
loop:
	for {
		select {
		case err := <-errCh:
			merr = multierror.Append(merr, err)
		case <-wgdCh:
			break loop
		}
	}
	return merr
}

func (c *sysdump) collectGops(ctx context.Context, l *log.Entry, pods []*corev1.Pod, containerName string, path func(string) string) error {
	errCh := make(chan error)
	wgdCh := make(chan struct{})
	var wg sync.WaitGroup
	for _, p := range pods {
		p := p
		for _, s := range gopsStats {
			s := s
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Run 'gops' on the pod.
				o, _, err := c.k.Exec(ctx, p.Namespace, p.Name, containerName, gopsCommand, s, gopsPID)
				if err != nil {
					errCh <- fmt.Errorf("failed to collect gops for %q (%q) in namespace %q: %w", p.Name, containerName, p.Namespace, err)
					return
				}
				// Dump the output to the temporary directory.
				if err := writeString(path(fmt.Sprintf(gopsFileName, p.Name, containerName, s)), string(o)); err != nil {
					errCh <- fmt.Errorf("failed to collect gops for %q (%q) in namespace %q: %w", p.Name, containerName, p.Namespace, err)
					return
				}
			}()
		}
	}
	go func() {
		wg.Wait()
		close(wgdCh)
	}()

	var merr error
loop:
	for {
		select {
		case err := <-errCh:
			merr = multierror.Append(merr, err)
		case <-wgdCh:
			break loop
		}
	}
	return merr
}

func (c *sysdump) collectLogs(ctx context.Context, l *log.Entry, pod []*corev1.Pod, sinceTime time.Time, limitBytes int64, path func(string) string) error {
	errCh := make(chan error)
	wgdCh := make(chan struct{})
	var wg sync.WaitGroup
	for _, p := range pod {
		p := p
		for _, d := range p.Spec.Containers {
			d := d
			wg.Add(1)
			go func() {
				defer wg.Done()
				l, err := c.k.GetLogs(ctx, p.Namespace, p.Name, d.Name, sinceTime, limitBytes, false)
				if err != nil {
					errCh <- fmt.Errorf("failed to collect logs for %q (%q) in namespace %q: %w", p.Name, d.Name, p.Namespace, err)
				}
				if err := writeString(path(fmt.Sprintf(ciliumLogsFileName, p.Name, d.Name)), l); err != nil {
					errCh <- fmt.Errorf("failed to collect logs for %q (%q) in namespace %q: %w", p.Name, d.Name, p.Namespace, err)
				}
				// Check if this container has restarted, in which case we should gather the previous one's logs too.
				previous := false
				for _, s := range p.Status.ContainerStatuses {
					s := s
					if s.Name == d.Name && s.RestartCount > 0 {
						previous = true
					}
				}
				if previous {
					c.o.Logger.Debugf("collecting logs for restarted container %q in pod %q in namespace %q", d.Name, p.Name, p.Namespace)
					u, err := c.k.GetLogs(ctx, p.Namespace, p.Name, d.Name, sinceTime, limitBytes, true)
					if err != nil {
						errCh <- fmt.Errorf("failed to collect previous logs for %q (%q) in namespace %q: %w", p.Name, d.Name, p.Namespace, err)
					}
					if err := writeString(path(fmt.Sprintf(ciliumPreviousLogsFileName, p.Name, d.Name)), u); err != nil {
						errCh <- fmt.Errorf("failed to collect previous logs for %q (%q) in namespace %q: %w", p.Name, d.Name, p.Namespace, err)
					}
				}
			}()
		}
	}
	go func() {
		wg.Wait()
		close(wgdCh)
	}()

	var merr error
loop:
	for {
		select {
		case err := <-errCh:
			merr = multierror.Append(merr, err)
		case <-wgdCh:
			break loop
		}
	}
	return merr
}

func filterPods(l *corev1.PodList, n []string) []*corev1.Pod {
	r := make([]*corev1.Pod, 0)
	for _, p := range l.Items {
		p := p
		if stringutils.Contains(n, p.Spec.NodeName) {
			r = append(r, &p)
		}
	}
	return r
}
