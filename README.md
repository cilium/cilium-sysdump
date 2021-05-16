# cilium-sysdump

The cilium-sysdump tool collects all information in a cluster required to troubleshoot issues with Cilium and Hubble.

# Important

`cilium-sysdump` is currently undergoing a rewrite.
If you're looking for a stable release and instructions, please check the [previous `README.md` file](README.prev.md).

# Using as a library

While a release of the new `cilium-sysdump` isn't available, you can import it from other projects by running

```bash
go get github.com/cilium/cilium-sysdump@go
```

# Installing

While a release of the new `cilium-sysdump` isn't available, you can get the binary by running

```bash
go install github.com/cilium/cilium-sysdump@go
```

Alternatively, you can run

```
git clone https://github.com/cilium/cilium-sysdump
cd cilium-sysdump
git checkout go
go run ./cmd/main.go
```

# Running

To capture a full sysdump of the Kubernetes cluster pointed at by the current context, run

```
cilium-sysdump
```

To use a particular kubeconfig file, run

```
cilium-sysdump --kubeconfig <path-to-kubeconfig>
```

To restrict the nodes targeted by gops and log collection, run

```
cilium-sysdump --nodes kubernetes-worker-1,kubernetes-worker-3
```

To get the full list of command-line flags run


```
cilium-sysdump --help
Usage:
  -cilium-labels string
        the labels used to target Cilium pods (default "k8s-app=cilium")
  -cilium-namespace string
        the namespace Cilium in running in (default "kube-system")
  -cilium-operator-labels string
        the labels used to target Cilium operator pods (default "io.cilium/app=operator")
  -cilium-operator-namespace string
        the namespace Cilium operator is running in (default "kube-system")
  -debug
        whether to enable debug logging
  -hubble-labels string
        the labels used to target Hubble pods (default "k8s-app=hubble")
  -hubble-namespace string
        the namespace Hubble is running in (default "kube-system")
  -hubble-relay-labels string
        the labels used to target Hubble Relay pods (default "k8s-app=hubble-relay")
  -hubble-relay-namespace string
        the namespace Hubble Relay is running in (default "kube-system")
  -hubble-ui-labels string
        the labels used to target Hubble UI pods (default "k8s-app=hubble-ui")
  -hubble-ui-namespace string
        the namespace Hubble UI is running in (default "kube-system")
  -kubeconfig string
         (default "/Users/cilium/.kube/config")
  -logs-limit-bytes int
        the limit on the number of bytes to use when collecting logs (default 1073741824)
  -logs-since-time duration
        how far back in time to go when collecting logs (default 8760h0m0s)
  -node-list string
        comma-separated list of node ips or names to filter pods for which to collect gops and logs by
  -output-filename string
        the name of the resulting file (without extension)
        '<ts>' can be used as the placeholder for the timestamp (default "cilium-sysdump-<ts>")
  -quick
        whether to enable quick mode (i.e. skip collection of cilium bugtool and logs)
```
