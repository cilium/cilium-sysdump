# cilium-sysdump

The cilium-sysdump tool collects all information in a cluster required to troubleshoot issues with Cilium and Hubble.

## Prerequisites
- Python >= 2.7
- kubectl

## Using cilium-sysdump

Download the latest version of the `cilium-sysdump` tool:

```sh
$ curl -sLO https://github.com/cilium/cilium-sysdump/releases/latest/download/cilium-sysdump.zip
```

Make sure `kubectl` is pointing to your cluster and run `cilium-sysdump` with:

```sh
$ python cilium-sysdump.zip
```

Note that by default `cilium-sysdump` will collect all the logs and for all the
nodes in the cluster.

To make sure the tool collects as much relevant logs as possible, and to reduce
the time required for this operation, it is advised to:

* set the `--since` option to go back in time to when the issues started
* set the `--nodes` option to pick only a few nodes in case the cluster has many of them
* set the `--size-limit` option to limit the size of the log files

The command with the aforementioned options set would look like:

```sh
$ python cilium-sysdump.zip --since $LOG_DURATION --nodes $NODE1_IP,$NODE2_IP
```

## Options
The following options are supported:

- `--cilium-labels CILIUM_LABELS`: labels of cilium pods running in the cluster
- `--cilium-ns CILIUM_NS`: specify the k8s namespace Cilium is running in
- `--hubble-labels HUBBLE_LABELS`: labels of hubble pods running in the cluster
- `--hubble-ns HUBBLE_NS`: specify the k8s namespace Hubble is running in
- `--hubble-relay-labels HUBBLE_RELAY_LABELS`: labels of hubble-relay pods running in the cluster
- `--hubble-relay-ns HUBBLE_RELAY_NS`: specify the k8s namespace Hubble-Relay is running in
- `--nodes NODES`: only return logs for particular nodes specified by a comma separated list of node IP addresses
- `--output OUTPUT`: output filename without .zip extension
- `--quick QUICK`: enable quick mode. Logs and cilium bugtool output will to "false"
- `--since SINCE`: only return logs newer than a relative duration like 5s, 2m, or 3h. Defaults to 0
- `--size-limit SIZE_LIMIT`: size limit (bytes) for the collected logs. Defaults to 1073741824 (1GB)
