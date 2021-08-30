#!/usr/bin/env python
# Copyright 2017-2020 Authors of Cilium
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import logging
import subprocess
import sys
import time

import net

FORMAT = '%(levelname)s %(message)s'
# TODO: Make the logging level configurable.
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=FORMAT)
if sys.stdout.isatty():
    # running in a real terminal
    # Color code source: http://bit.ly/2zPHiCK
    logging.addLevelName(
        logging.WARNING,
        "\033[1;31m%s\033[1;0m" %
        logging.getLevelName(
            logging.WARNING))
    logging.addLevelName(
        logging.ERROR,
        "\033[1;41m%s\033[1;0m" %
        logging.getLevelName(
            logging.ERROR))
log = logging.getLogger(__name__)


ResourceStatus_ = collections.namedtuple(
    'ResourceStatus',
    'namespace name')


# Unlike PodStatus, this class provides an easy-to-extend generic k8s
# resource representation. Feel free to append more resource status.
class ResourceStatus(ResourceStatus_):
    """ A namedtupe with the following elements in this order.
        namespace (string): name of the pod.
        name (string): name of the pod.
    """
    pass


def get_resource_status(type, full_name="", label="", must_exist=True):
    """Returns the ResourceStatus of one particular Kubernetes resource.

    Args:
        type - Kubernetes resource type.
        full_name(optional) - the full name of the Kubernetes resource.
        label(optional) - the attached label of the resource.
        must_exist(optional) - whether to resource must exist.
    Returns:
        An object of type ResourceStatus.
    Exceptions:
        The goal is to be consistent with get_pod_status.
        If the command execution failed or no resource has been
        found. A RuntimeError exception will be threw.
    """
    cmd = "kubectl get {} --no-headers --all-namespaces " \
          "-o wide --selector \"{}\" " \
          "| grep \"{}\" | awk '{{print $1 \" \" $2}}'"
    cmd = cmd.format(type, label, full_name)
    try:
        encoded_output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as exc:
        log.warning("command to get status of {} has "
                    "failed. error code: "
                    "{} {}".format(full_name,
                                   exc.returncode, exc.output))
        raise RuntimeError(
            "command to get status of {} has "
            "failed. error code: "
            "{} {}".format(full_name,
                           exc.returncode, exc.output))
    output = encoded_output.decode()
    if output == "":
        if not must_exist:
            return None
        log.warning(
            "{} \"{}\" with label \"{}\" can't be found in "
            "the cluster".format(type, full_name, label))
        raise RuntimeError(
            "{} {} with label {} can't be found in the cluster".format(
                type, full_name, label))
    # Example line:
    # kube-system cilium
    split_line = output.split(' ')
    return ResourceStatus(namespace=split_line[0],
                          name=split_line[1])


PodStatus_ = collections.namedtuple('PodStatus',
                                    'name ready_status status node_name '
                                    'namespace')


class PodStatus(PodStatus_):
    """ A namedtupe with the following elements in this order.
        name (string): name of the pod.
        ready_status (string): the ready status of the pod.
        status (string): the status of the pod (e.g. Running).
        node_name (string): the name of the node.
        namespace (string): the namespace of the pod
    """
    pass


def get_pods_filtered(custom_columns, filter, must_exist=True):
    """Returns a list of pods filtered by the provided filter. The pod list is
       retrieved by using custom columns.

    Args:
        custom_columns - the custom columns to fetch, e.g. pod name, node IP,
                         etc. See
                         https://kubernetes.io/docs/reference/kubectl/overview/#custom-columns.
        filter - a list to filter the pods output by, e.g. node names / IPs.
        must_exist - boolean to indicate that we should not get back empty
                     output. If the condition isn't satisfied, an error will be
                     logged.

    Returns:
        A list of strings representing `kubectl get pods` output.
    """
    cc_template = "-o=custom-columns={}"
    cmd_template = "kubectl get pods --no-headers --all-namespaces {} | " \
        "grep -E \"{}\" | awk '{{print $1}}'"

    filter_cmd = cmd_template.format(
        cc_template.format(custom_columns),  # Plugs into `-o=custom-columns=`
        "|".join(map(str, filter))           # Plugs into `grep -E`
    )
    try:
        filter_output = subprocess.check_output(
            filter_cmd, shell=True, stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as exc:
        log.error("command to list filtered pods has "
                  "failed. error code: "
                  "{} {}".format(exc.returncode, exc.output))
    filter_output = filter_output.decode()
    if filter_output == "":
        if must_exist:
            log.error("No output because all the pods were filtered "
                      "out by the node filter {}.".format(filter))
        return []

    return filter_output.splitlines()


def get_pods_status_iterator_by_labels(label_selector, node_filter,
                                       must_exist=True):
    """Returns an iterator to the status of pods selected with the
    label selector.

    Args:
        label_selector - the labels used to select the pods.
        e.g. "k8s-app=cilium, kubernetes.io/cluster-service=true"
        must_exist - boolean to indicate that a pod with that name must exist.
            If the condition isn't satisfied, an error will be logged.

    Returns:
        An object of type PodStatus.
    """
    # TODO: Handle the case of a pod w/ multiple containers.
    # Right now, we pick the status of the first container in the pod.
    cmd = ("kubectl get pods --all-namespaces -o wide"
           " --selector={} -o=jsonpath='{{range .items[*]}}"
           "{{@.metadata.name}}{{\" \"}}"
           "{{@.status.containerStatuses[0].ready}}{{\" \"}}"
           "{{@.status.phase}}{{\" \"}}"
           "{{@.spec.nodeName}}{{\" \"}}"
           "{{@.metadata.namespace}}{{\"\\n\"}}'").format(label_selector)
    try:
        encoded_output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as exc:
        log.error("command to get status of {} has "
                  "failed. error code: "
                  "{} {}".format(label_selector,
                                 exc.returncode, exc.output))
        return
    output = encoded_output.decode()
    if output == "":
        if must_exist:
            log.warning("no pods with labels {} are running on the cluster"
                        .format(label_selector))
        return

    # Separate out IPs and node names if the input from user is mixed.
    ip_filter = [s for s in node_filter if net.is_ipaddress(s)]
    name_filter = [s for s in node_filter if not net.is_ipaddress(s)]

    # Retrieve pods based on filter provided by user. If the input is mixed
    # (both IPs and node names), then we will aggregate all the output together
    # in the end. If no filter is provided at all, we fall back to fetching
    # everything.
    filtered_pod_list = []
    if ip_filter:
        # kubectl field selector supports listing pods based on a particular
        # field. However, it doesn't support hostIP field in 1.9.6. Also,
        # it doesn't support set-based filtering. As a result, we will use
        # grep based filtering for now. We might want to switch to this
        # feature in the future. The following filter can be extended by
        # modifying the following kubectl custom-columns and the associated
        # grep command.
        log.info("filtering on node IP address ...")
        filtered_pod_list += get_pods_filtered(
            "NAME:.metadata.name,HOSTIP:.status.hostIP",
            ip_filter,
            must_exist
        )
    if name_filter:
        log.info("filtering on node name ...")
        filtered_pod_list += get_pods_filtered(
            "NAME:.metadata.name,NODE:.spec.nodeName",
            name_filter,
            must_exist
        )
    if not ip_filter and not name_filter:
        filtered_pod_list += get_pods_filtered(
            "NAME:.metadata.name",
            [],
            must_exist
        )

    for line in output.splitlines():
        # Example line:
        # name-blah-sr64c 0/1 CrashLoopBackOff
        # ip-172-0-33-255.us-west-2.compute.internal kube-system
        split_line = line.split(' ')
        if split_line[0] not in filtered_pod_list:
            continue
        yield PodStatus(name=split_line[0],
                        ready_status=split_line[1],
                        status=split_line[2],
                        node_name=split_line[3],
                        namespace=split_line[4])


def get_container_names_per_pod(pod_namespace, pod_name, init_containers=True):
    """Return the list of container names in the given pod"""
    cmd = "kubectl get pods {} -n {} " \
          "-o jsonpath='{} {}'".format(
              pod_name, pod_namespace, "{.spec.containers[*].name}",
              "{.spec.initContainers[*].name}" if init_containers else ""
          )

    output = b''
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError:
        pass
    output = output.decode().strip()
    if not output:
        log.error("Error: Could not collect pod container name(s) for {}/{}"
                  .format(pod_namespace, pod_name))
        return []
    return output.split(" ")


def get_nodes():
    """Return the list of nodes in the entire cluster"""
    cmd = "kubectl get nodes " \
          "-o jsonpath='{}'".format("{.items[*].metadata.name}")

    output = b''
    try:
        output = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError:
        pass
    output = output.decode().strip()
    if not output:
        log.error("Error: Could not collect nodes in the cluster")
        return []
    return output.split(" ")


def get_current_time():
    return time.strftime("%Y%m%d-%H%M%S")
