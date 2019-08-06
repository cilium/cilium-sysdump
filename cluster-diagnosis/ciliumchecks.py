#!/usr/bin/env python
# Copyright 2017 Authors of Cilium
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
import namespace

import subprocess
import utils
import re
import logging
log = logging.getLogger(__name__)

MINIMUM_SUPPORTED_CILIUM_VERSION_MAJOR = 1
MINIMUM_SUPPORTED_CILIUM_VERSION_MINOR = 0
MINIMUM_SUPPORTED_CILIUM_VERSION_PATCH = 0


def check_pod_running_cb(nodes, cilium_labels):
    """Checks whether the Cilium container is running on all the nodes.

    Args:
        nodes -- list of nodes where the cilium pod is expected
         to be running

    Returns:
        True if successful, False otherwise.
    """
    ret_code = True
    pod_not_seen_on_nodes = nodes[:]
    for name, ready_status, status, node_name, namespace in \
            utils.get_pods_summarized_status_iterator(cilium_labels):
        try:
            pod_not_seen_on_nodes.remove(node_name)
        except ValueError:
            pass
        if status != utils.STATUS_RUNNING or ready_status != "true":
            log.error("pod {} running on {} has ready status"
                      " {} and status {}".format(
                          name, node_name, ready_status, status))
            # Check the log for common errors.
            cmd = "kubectl logs -n {} {}".format(namespace, name)
            output = ""
            try:
                encoded_output = subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError as exc:
                log.error(
                    "command to get the Cilium logs has failed. "
                    "error code: {} {}".format(exc.returncode, exc.output))
                ret_code = False
                continue
            output = encoded_output.decode()
            ret_code = False
            # Check whether the KV store configuration is bad.
            if "Unable to setup kvstore" in output:
                log.error("Hint: Check KV-store configuration")
                # Print the exact log message
                log.error(output.splitlines()[-1])
            # Check whether the kernel is too old.
            elif "kernel version: NOT OK: minimal supported" \
                 " kernel version is >= 4.8" in output:
                log.error("Hint: Unsupported kernel version; Please "
                          "install Cilium on Linux kernel >= 4.8")
                # Print the exact log message
                log.error(output.splitlines()[-1])
            elif "Unable to contact kubernetes api-server" in output:
                log.error("Hint: Cilium is unable to connect to "
                          "the kube-apiserver")
                # Print the exact log message
                log.error(output.splitlines()[-1])
            elif "linking environment: OK!" not in output:
                log.error("Hint: linking environment error. Check"
                          " Cilium logs for more information.")
            elif "bpf_requirements check: OK!" not in output:
                log.error("Hint: BPF requirements have not been met. Check"
                          " Cilium logs for more information.")
        else:
            log.info("pod {} running on {} has pod ready status {}"
                     " and status {}".format(
                         name,
                         node_name,
                         ready_status,
                         status))

    if len(pod_not_seen_on_nodes) != 0:
        if len(pod_not_seen_on_nodes) == len(nodes):
            log.error("could not find a running cilium pod on any node")
            ret_code = False
        else:
            log.warning("could not find a running cilium pod on node(s): "
                        "{}".format(pod_not_seen_on_nodes))
    return ret_code


def check_access_log_config_cb(cilium_labels):
    """Checks cilium access log parameter.

    Args:
        None

    Returns:
        True if successful, False otherwise.
    """
    ret_code = True
    for name, ready_status, status, node_name in \
            utils.get_pods_status_iterator_by_labels(cilium_labels, []):
        # TODO: Add volume checks.
        config = utils.get_pod_config(name)
        if not config:
            log.warn('could not check access log configuration on cilium'
                     ' pod {} on node {}'.format(name, node_name))
            ret_code = False
            continue
        if re.search('^.*--access-log.*/var/run/cilium/access.log.*',
                     config, re.DOTALL) is None:
            log.warn('cilium pod {} on node {} '
                     'has not been configured with '
                     '--access-log parameter or the '
                     'access log filename is incorrect.'
                     ' Fix this if you would like'
                     ' to see Layer 7 proxy logs.'.format(
                         name,
                         node_name))
            ret_code = False
        else:
            log.info('cilium pod {} on node {} '
                     'has been configured with '
                     '--access-log parameter and the '
                     'access log filename is correct'.format(
                         name,
                         node_name))
    return ret_code


def check_drop_notifications_enabled_cb(cilium_labels):
    """Checks whether DropNotification is enabled

    Args:
        None

    Returns:
        True if successful, False otherwise.
    """
    ret_code = True
    for name, ready_status, status, node_name, namespace in \
            utils.get_pods_status_iterator_by_labels(cilium_labels, []):
        cmd = ("kubectl exec -it {}"
               " -n {} cilium config "
               "| grep DropNotification "
               "| awk '{{print $2}}'").format(name, namespace)
        output = ""
        try:
            encoded_output = subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as grepexc:
            log.error("command to fetch cilium config has failed."
                      "error code: {} {}".format(grepexc.returncode,
                                                 grepexc.output))
            ret_code = False
            continue
        output = encoded_output.decode()
        if "Enabled" not in output.strip(' \t\n\r'):
            # Can't use exact match/string comparison as the output has
            # ASCII-encoded characters.
            log.error('cilium pod {} on '
                      'node {} has DropNotifications {}'.format(
                          name,
                          node_name,
                          repr(output.strip(' \t\n\r'))))
            ret_code = False
        else:
            log.info('cilium pod {} on '
                     'node {} has DropNotifications {}'.format(
                         name,
                         node_name,
                         output.strip(' \t\n\r')))
    return ret_code


def check_trace_notifications_enabled_cb(cilium_labels):
    """Checks whether TraceNotification is enabled

    Args:
        None

    Returns:
        True if successful, False otherwise.
    """
    ret_code = True
    for name, ready_status, status, node_name, namespace in \
            utils.get_pods_status_iterator_by_labels(cilium_labels, []):
        cmd = ("kubectl exec -it {}"
               " -n {} cilium config "
               "| grep TraceNotification "
               "| awk '{{print $2}}'").format(name, namespace)
        output = ""
        try:
            encoded_output = subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as grepexc:
            log.error("command to fetch cilium config has failed."
                      "error code: {} {}".format(grepexc.returncode,
                                                 grepexc.output))
            ret_code = False
            continue
        output = encoded_output.decode()
        if "Enabled" not in output.strip(' \t\n\r'):
            # Can't use exact match/string comparison as the output has
            # ASCII-encoded characters.
            log.error('cilium pod {} on '
                      'node {} has TraceNotifications {}'.format(
                          name,
                          node_name,
                          repr(output.strip(' \t\n\r'))))
            ret_code = False
        else:
            log.info('cilium pod {} on '
                     'node {} has TraceNotifications {}'.format(
                         name,
                         node_name,
                         output.strip(' \t\n\r')))
    return ret_code


def check_cilium_version_cb(cilium_labels):
    """Checks whether cilium version is >= minimum supported version.

    Args:
        None

    Returns:
        True if successful, False otherwise.
    """
    ret_code = True
    for name, ready_status, status, node_name, namespace in \
            utils.get_pods_status_iterator_by_labels(cilium_labels, []):
        cmd = ("kubectl get pod {}"
               " -n {} -o jsonpath='{{.spec.containers"
               "[?(@.command[]==\"cilium-agent\")].image}}' | "
               "awk -F \":\" '{{print $2}}'")\
            .format(name, namespace)
        output = ""
        try:
            encoded_output = subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as grepexc:
            log.error("command to fetch cilium version has failed."
                      "error code: {} {}".format(grepexc.returncode,
                                                 grepexc.output))
            ret_code = False
            break
        output = encoded_output.decode().strip(' \t\n\r')
        m = re.match(r"v(\d+).(\d+).(\d+)", output)
        if not m:
            log.warning("cilium version {} not in the expected format "
                        "vX.Y.Z".format(output))
            ret_code = True
            break

        major = int(m.group(1))
        minor = int(m.group(2))
        patch = int(m.group(3))

        print_error = True
        if major > MINIMUM_SUPPORTED_CILIUM_VERSION_MAJOR:
            print_error = False
        elif major == MINIMUM_SUPPORTED_CILIUM_VERSION_MAJOR:
            if minor > MINIMUM_SUPPORTED_CILIUM_VERSION_MINOR:
                print_error = False
            elif minor == MINIMUM_SUPPORTED_CILIUM_VERSION_MINOR:
                if patch >= MINIMUM_SUPPORTED_CILIUM_VERSION_PATCH:
                    print_error = False

        if print_error:
            log.error('cilium version is {}. Minimum supported '
                      'version is: v{}.{}.{}'.format(
                       output, MINIMUM_SUPPORTED_CILIUM_VERSION_MAJOR,
                       MINIMUM_SUPPORTED_CILIUM_VERSION_MINOR,
                       MINIMUM_SUPPORTED_CILIUM_VERSION_PATCH))
            ret_code = False
        else:
            log.info('cilium version is {}'.format(output))

        break  # We do not need to inspect every cilium pod. Break here.

    return ret_code
