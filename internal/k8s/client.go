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

package k8s

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

type Client interface {
	GetFileContents(ctx context.Context, namespace, name, container, srcPath string) ([]byte, error)
	Exec(ctx context.Context, namespace, name, container string, command ...string) ([]byte, []byte, error)
	GetCiliumClusterWideNetworkPolicies(ctx context.Context) (*ciliumv2.CiliumClusterwideNetworkPolicyList, error)
	GetCiliumEndpoints(ctx context.Context) (*ciliumv2.CiliumEndpointList, error)
	GetCiliumIdentities(ctx context.Context) (*ciliumv2.CiliumIdentityList, error)
	GetCiliumNetworkPolicies(ctx context.Context) (*ciliumv2.CiliumNetworkPolicyList, error)
	GetCiliumNodes(ctx context.Context) (*ciliumv2.CiliumNodeList, error)
	GetConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error)
	GetDaemonSet(ctx context.Context, namespace, name string) (*appsv1.DaemonSet, error)
	GetDeployment(ctx context.Context, namespace, name string) (*appsv1.Deployment, error)
	GetEvents(ctx context.Context) (*corev1.EventList, error)
	GetLogs(ctx context.Context, namespace, name, container string, sinceTime time.Time, limitBytes int64, previous bool) (string, error)
	GetNamespaces(ctx context.Context) (*corev1.NamespaceList, error)
	GetNetworkPolicies(ctx context.Context) (*networkingv1.NetworkPolicyList, error)
	GetNodes(ctx context.Context) (*corev1.NodeList, error)
	GetPods(ctx context.Context, namespace, labelSelector string) (*corev1.PodList, error)
	GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error)
	GetPodsTable(ctx context.Context) (*metav1.Table, error)
	GetServices(ctx context.Context) (*corev1.ServiceList, error)
	GetVersion(ctx context.Context) (string, error)
}

type client struct {
	c cilium.Interface
	k kubernetes.Interface
	r genericclioptions.RESTClientGetter
}

func NewClient(r genericclioptions.RESTClientGetter) (Client, error) {
	_ = ciliumv2.AddToScheme(scheme.Scheme)
	f, err := r.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}
	k, err := kubernetes.NewForConfig(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}
	c, err := cilium.NewForConfig(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}
	return &client{
		c: c,
		k: k,
		r: r,
	}, nil
}

func (c *client) Exec(ctx context.Context, namespace, name, container string, command ...string) ([]byte, []byte, error) {
	r := c.k.CoreV1().RESTClient().
		Get().
		Namespace(namespace).
		Resource("pods").
		Name(name).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command:   command,
			Container: container,
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, runtime.NewParameterCodec(scheme.Scheme))
	k, err := c.r.ToRESTConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Kubernetes config: %w", err)
	}
	x, err := remotecommand.NewSPDYExecutor(k, "POST", r.URL())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create executor: %w", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err = x.Stream(remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("executor failed to stream: %w", err)
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func (c *client) GetFileContents(ctx context.Context, namespace, name, container, srcPath string) ([]byte, error) {
	o, _, err := c.Exec(ctx, namespace, name, container, "cat", srcPath)
	return o, err
}

func (c *client) GetCiliumClusterWideNetworkPolicies(ctx context.Context) (*ciliumv2.CiliumClusterwideNetworkPolicyList, error) {
	return c.c.CiliumV2().CiliumClusterwideNetworkPolicies().List(ctx, metav1.ListOptions{})
}

func (c *client) GetCiliumEndpoints(ctx context.Context) (*ciliumv2.CiliumEndpointList, error) {
	return c.c.CiliumV2().CiliumEndpoints(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
}

func (c *client) GetCiliumIdentities(ctx context.Context) (*ciliumv2.CiliumIdentityList, error) {
	return c.c.CiliumV2().CiliumIdentities().List(ctx, metav1.ListOptions{})
}

func (c *client) GetCiliumNetworkPolicies(ctx context.Context) (*ciliumv2.CiliumNetworkPolicyList, error) {
	return c.c.CiliumV2().CiliumNetworkPolicies(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
}

func (c *client) GetCiliumNodes(ctx context.Context) (*ciliumv2.CiliumNodeList, error) {
	return c.c.CiliumV2().CiliumNodes().List(ctx, metav1.ListOptions{})
}

func (c *client) GetConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	return c.k.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *client) GetDaemonSet(ctx context.Context, namespace, name string) (*appsv1.DaemonSet, error) {
	return c.k.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *client) GetDeployment(ctx context.Context, namespace, name string) (*appsv1.Deployment, error) {
	return c.k.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *client) GetEvents(ctx context.Context) (*corev1.EventList, error) {
	return c.k.CoreV1().Events(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
}

func (c *client) GetLogs(ctx context.Context, namespace, name, container string, sinceTime time.Time, limitBytes int64, previous bool) (string, error) {
	t := metav1.NewTime(sinceTime)
	o := corev1.PodLogOptions{
		Container:  container,
		Follow:     false,
		LimitBytes: &limitBytes,
		Previous:   previous,
		SinceTime:  &t,
		Timestamps: true,
	}
	r := c.k.CoreV1().Pods(namespace).GetLogs(name, &o)
	s, err := r.Stream(ctx)
	if err != nil {
		return "", err
	}
	defer s.Close()
	var b bytes.Buffer
	if _, err = io.Copy(&b, s); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (c *client) GetNamespaces(ctx context.Context) (*corev1.NamespaceList, error) {
	return c.k.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
}

func (c *client) GetNetworkPolicies(ctx context.Context) (*networkingv1.NetworkPolicyList, error) {
	return c.k.NetworkingV1().NetworkPolicies(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
}

func (c *client) GetNodes(ctx context.Context) (*corev1.NodeList, error) {
	return c.k.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
}

func (c *client) GetPods(ctx context.Context, namespace, labelSelector string) (*corev1.PodList, error) {
	return c.k.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
}

func (c *client) GetPodsTable(ctx context.Context) (*metav1.Table, error) {
	r := resource.NewBuilder(c.r).
		Unstructured().
		AllNamespaces(true).
		ResourceTypes("pods").
		SingleResourceType().
		SelectAllParam(true).
		RequestChunksOf(500).
		ContinueOnError().
		Latest().
		Flatten().
		TransformRequests(func(r *rest.Request) {
			r.SetHeader(
				"Accept", fmt.Sprintf("application/json;as=Table;v=%s;g=%s", metav1.SchemeGroupVersion.Version, metav1.GroupName),
			)
		}).
		Do()
	if r.Err() != nil {
		return nil, r.Err()
	}
	i, err := r.Infos()
	if err != nil {
		return nil, err
	}
	if len(i) != 1 {
		return nil, fmt.Errorf("expected a single kind of resource (got %d)", len(i))
	}
	return unstructuredToTable(i[0].Object)
}

func (c *client) GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	return c.k.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *client) GetServices(ctx context.Context) (*corev1.ServiceList, error) {
	return c.k.CoreV1().Services(corev1.NamespaceAll).List(ctx, metav1.ListOptions{})
}

func (c *client) GetVersion(_ context.Context) (string, error) {
	v, err := c.k.Discovery().ServerVersion()
	if err != nil {
		return "", fmt.Errorf("failed to get Kubernetes version: %w", err)
	}
	return fmt.Sprintf("%#v", *v), nil
}
