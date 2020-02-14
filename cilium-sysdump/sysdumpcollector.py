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
import namespace

import json
import logging
import multiprocessing
import re
import os
import functools
import shutil
import subprocess
import utils

from multiprocessing.pool import ThreadPool

log = logging.getLogger(__name__)


class SysdumpCollector(object):
    """Collects logs and other useful information for debugging.

    Args:
        sysdump_dir_name: the sysdump file name.
        since: the relative duration duration (like 5s, 2m, or 3h) used to
            decide how old the logs can be for them to be collected.
        size_limit: size limit (MB) for the collected logs.
    """

    def __init__(
            self,
            sysdump_dir_name, since, size_limit, output, is_quick_mode,
            cilium_labels, hubble_labels):
        self.sysdump_dir_name = sysdump_dir_name
        self.since = since
        self.size_limit = size_limit
        self.output = output
        self.is_quick_mode = is_quick_mode
        self.cilium_labels = cilium_labels
        self.hubble_labels = hubble_labels

    def collect_nodes_overview(self):
        nodes_overview_file_name = "nodes-{}.json".format(
            utils.get_current_time())
        cmd = "kubectl get nodes -o json > {}/{}".format(
              self.sysdump_dir_name, nodes_overview_file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Could not collect nodes overview: {}".
                          format(exc, nodes_overview_file_name))
        else:
            log.info("collected nodes overview: {}"
                     .format(nodes_overview_file_name))

    def collect_pods_overview(self):
        pods_overview_file_name = "pods-{}.json".format(
            utils.get_current_time())
        cmd = "kubectl get pods -o json --all-namespaces > {}/{}".format(
              self.sysdump_dir_name, pods_overview_file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Could not collect pods overview: {}".
                          format(exc, pods_overview_file_name))
        else:
            log.info("collected pods overview: {}"
                     .format(pods_overview_file_name))

    def collect_pods_summary(self):
        pods_summary_file_name = "pods-{}.txt".format(
            utils.get_current_time())
        cmd = "kubectl get pods --all-namespaces -o wide > {}/{}".format(
              self.sysdump_dir_name, pods_summary_file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Could not collect pods summary: {}".
                          format(exc, pods_summary_file_name))
        else:
            log.info("collected pods summary: {}"
                     .format(pods_summary_file_name))

    def collect_logs(self, label_selector, node_ip_filter):
        pool = ThreadPool(min(32, multiprocessing.cpu_count() + 4))

        pool.map(
            self.collect_logs_per_pod,
            utils.get_pods_status_iterator_by_labels(
                label_selector,
                node_ip_filter))
        pool.close()
        pool.join()

    def collect_logs_per_pod(self, podstatus):
        containers = utils.get_container_names_per_pod(podstatus.namespace,
                                                       podstatus.name)
        for container in containers:
            log_file_name = "{}-{}".format(podstatus.name,
                                           utils.get_current_time())
            command = "kubectl logs {} --container={} --timestamps=true " \
                      "--since={} --limit-bytes={} -n {} > {}/{}.log"
            cmd = command.format(
                podstatus.name, container, self.since, self.size_limit,
                podstatus.namespace, self.sysdump_dir_name, log_file_name)
            try:
                subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 0:
                    log.error("Error: {}. Could not collect log file: {}"
                              .format(exc, log_file_name))
            else:
                log.info("collected log file: {}".format(log_file_name))

            # Only get logs from previous containers if pod has restarted.
            # Need to get the pod to access its restartCount.
            podCommandPreFormatted = "kubectl get pod {} -n {} -o json"
            podCmd = podCommandPreFormatted.format(
                podstatus.name, podstatus.namespace,
            )

            try:
                podOutput = subprocess.check_output(podCmd, shell=True)
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 0:
                    log.debug("Debug {}: could not get pod {}").format(
                        exc, podstatus[0])
            else:
                # Examine JSON output to see if restartCount > 0
                decodedPodOutput = podOutput.decode()
                jsonOutput = json.loads(decodedPodOutput)
                containerStatuses = jsonOutput['status']['containerStatuses']

                gatherPrevLogs = False

                for value in containerStatuses:
                    restartCount = value['restartCount']
                    if int(restartCount) > 0:
                        gatherPrevLogs = True
                        break
                if gatherPrevLogs:
                    log_file_name_previous = "{0}-previous".format(
                        log_file_name)
                    command = "kubectl logs --previous --timestamps=true " \
                              "--container={} " \
                              "--since={} " \
                              "--limit-bytes={} -n {} {} > {}/{}.log"
                    cmd = command.format(container, self.since,
                                         self.size_limit,
                                         podstatus.namespace, podstatus.name,
                                         self.sysdump_dir_name,
                                         log_file_name_previous)
                    try:
                        subprocess.check_output(cmd, shell=True)
                    except subprocess.CalledProcessError as exc:
                        if exc.returncode != 0:
                            log.debug(
                                "Debug: {}. Could not collect previous "
                                "log for '{}': {}"
                                .format(exc, podstatus.name, log_file_name))
                    else:
                        log.info("collected log file: {}".format(
                            log_file_name_previous))

                else:
                    log.debug("no previous pod logs to gather for "
                              "pod/container {}/{}".format(
                                  podstatus.name, container))

    def collect_gops_stats(self, label_selector, node_ip_filter):
        self.collect_gops(label_selector, node_ip_filter, "stats")
        self.collect_gops(label_selector, node_ip_filter, "memstats")
        self.collect_gops(label_selector, node_ip_filter, "stack")

    def collect_gops(self, label_selector, node_ip_filter, type_of_stat):
        pool = ThreadPool(min(32, multiprocessing.cpu_count() + 4))
        pool.map(
            functools.partial(self.collect_gops_per_pod,
                              type_of_stat=type_of_stat),
            utils.get_pods_status_iterator_by_labels(
                label_selector, node_ip_filter))
        pool.close()
        pool.join()

    def collect_gops_per_pod(self, podstatus, type_of_stat):
        containers = utils.get_container_names_per_pod(podstatus.namespace,
                                                       podstatus.name)
        for container in containers:
            if container == "hubble-ui":
                continue  # gops does not run in hubble-ui container
            file_name = "{}-{}-{}-{}.txt".format(
                podstatus.name,
                container,
                utils.get_current_time(),
                type_of_stat)
            cmd = "kubectl exec -n {} {} -c {} -- /bin/gops {} 1 > {}/{}" \
                  .format(podstatus.namespace, podstatus.name, container,
                          type_of_stat, self.sysdump_dir_name, file_name)
            try:
                subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 0:
                    log.warning("Warning: {}. Could not collect gops {}: {}"
                                .format(exc, type_of_stat, file_name))
            else:
                log.info("collected gops {} file: {}".format(
                    type_of_stat, file_name))

    def collect_netpol(self):
        netpol_file_name = "netpol-{}.yaml".format(utils.get_current_time())
        cmd = "kubectl get netpol -o yaml --all-namespaces > {}/{}".format(
              self.sysdump_dir_name, netpol_file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.warning("Warning: {}. Could not collect kubernetes network"
                            " policy: {}".format(exc, netpol_file_name))
        else:
            log.info("collected kubernetes network policy: {}"
                     .format(netpol_file_name))

    def collect_cnp(self):
        cnp_file_name = "cnp-{}.yaml".format(utils.get_current_time())
        cmd = "kubectl get cnp -o yaml --all-namespaces > {}/{}".format(
              self.sysdump_dir_name, cnp_file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.warning("Warning: {}. Could not collect cilium network "
                            "policy: {}".format(exc, cnp_file_name))
        else:
            log.info("collected cilium network policy: {}"
                     .format(cnp_file_name))

    def collect_cep(self):
        cep_file_name = "cep-{}.yaml".format(utils.get_current_time())
        cmd = "kubectl get cep -o yaml --all-namespaces > {}/{}".format(
            self.sysdump_dir_name, cep_file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Could not collect cilium endpoints {}"
                          .format(exc, cep_file_name))
        else:
            log.info("collected cilium endpoints: {}".format(cep_file_name))

    def collect_daemonset_yaml(self, name="cilium"):
        ns = namespace.cilium_ns
        if name == "hubble":
            ns = namespace.hubble_ns
        file_name = "{}-ds-{}.yaml".format(name, utils.get_current_time())
        cmd = "kubectl get ds {} -n {} -oyaml > {}/{}".format(
            name, ns, self.sysdump_dir_name, file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.warning("Warning: {}. Unable to get {} daemonset yaml"
                            .format(exc, name))
        else:
            log.info("collected {} daemonset yaml file: {}".format(
                name, file_name))

    def collect_cilium_configmap(self):
        configmap_file_name = "cilium-configmap-{}.yaml".format(
            utils.get_current_time())
        cmd = "kubectl get configmap cilium-config -n {} -oyaml " \
              "> {}/{}".format(namespace.cilium_ns,
                               self.sysdump_dir_name, configmap_file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.warning("Warning: {}. Unable to get cilium configmap yaml"
                            .format(exc))
        else:
            log.info("collected cilium configmap yaml file: {}".format(
                configmap_file_name))

    def collect_cilium_secret(self):
        secret_file_name = "cilium-etcd-secrets-{}.json".format(
            utils.get_current_time())
        cmd = "kubectl get secret cilium-etcd-secrets -n {} -o json".format(
            namespace.cilium_ns)
        try:
            output = json.loads(
                subprocess.check_output(cmd, shell=True).decode("utf-8"))
            data = {}
            for key, value in output.get('data').items():
                data[key] = "XXXXX"
            output['data'] = data
            with open(
                os.path.join(self.sysdump_dir_name,
                             secret_file_name), 'w') as fp:
                fp.write(json.dumps(output))
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.warning("Warning: {}. Unable to get and redact cilium "
                            "secret".format(exc))
        else:
            log.info("collected and redacted cilium secret file: {}".format(
                secret_file_name))

    def collect_cilium_bugtool_output(self, label_selector, node_ip_filter):
        pool = ThreadPool(min(32, multiprocessing.cpu_count() + 4))
        pool.map(
            self.collect_cilium_bugtool_output_per_pod,
            utils.get_pods_status_iterator_by_labels(
                label_selector, node_ip_filter))
        pool.close()
        pool.join()

    def collect_cilium_bugtool_output_per_pod(self, podstatus):
        bugtool_output_dir = "bugtool-{}-{}".format(
            podstatus.name, utils.get_current_time())
        bugtool_output_file_name = "{}.tar".format(bugtool_output_dir)
        cmd = "kubectl exec -n {} {} cilium-bugtool".format(
            podstatus.namespace, podstatus.name)
        try:
            encoded_output = subprocess.check_output(cmd.split(), shell=False)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error(
                    "Error: {}. Could not run cilium-bugtool on {}"
                    .format(exc, podstatus.name))
        else:
            output = encoded_output.decode()
            p = re.compile(
                "^ARCHIVE at (.*)$")
            output_file_name = ""
            for line in output.splitlines():
                match = p.search(line)
                if match:
                    output_file_name = match.group(1)
            if output_file_name == "":
                log.error(
                    "Error: could not find cilium-bugtool output file name",
                )

            copyCmd = "kubectl cp {}/{}:{} ./{}/{}".format(
                podstatus.namespace, podstatus.name, output_file_name,
                self.sysdump_dir_name, bugtool_output_file_name)
            mkdirCmd = "mkdir -p ./{}/{}".format(
                    self.sysdump_dir_name, bugtool_output_dir)
            tarCmd = "tar -xf ./{}/{} -C ./{}/{} --strip-components=1".format(
                self.sysdump_dir_name, bugtool_output_file_name,
                self.sysdump_dir_name, bugtool_output_dir)
            rmCmd = "rm ./{}/{}".format(
                    self.sysdump_dir_name, bugtool_output_file_name)
            try:
                subprocess.check_output(copyCmd.split(), shell=False)
                subprocess.check_output(mkdirCmd.split(), shell=False)
                subprocess.check_output(tarCmd.split(), shell=False)
                subprocess.check_output(rmCmd.split(), shell=False)
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 0:
                    log.error(
                        "Error: {} Could not collect cilium-bugtool"
                        " output: {}".format(
                            exc, bugtool_output_file_name))
            else:
                log.info("collected cilium-bugtool output: {}".format(
                    bugtool_output_file_name))

    def collect_services_overview(self):
        svc_file_name = "services-{}.yaml".format(
            utils.get_current_time())
        cmd = "kubectl get svc --all-namespaces -oyaml " \
              "> {}/{}".format(self.sysdump_dir_name, svc_file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Unable to get svc overview")
        else:
            log.info("collected svc overview: {}".format(svc_file_name))

    def collect_k8s_version_info(self):
        version_file_name = "k8s-version-info-{}.txt".format(
            utils.get_current_time())
        cmd = "kubectl version > {}/{}".format(self.sysdump_dir_name,
                                               version_file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Unable to get kubernetes version info")
        else:
            log.info("collected kubernetes version info: {}"
                     .format(version_file_name))

    def collect_k8s_events(self):
        events_file_name = "k8s-events-{}.json".format(
            utils.get_current_time())
        cmd = "kubectl get events --all-namespaces -o json > {}/{}".format(
                self.sysdump_dir_name, events_file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Unable to get kubernetes events.")
        else:
            log.info("collected kubernetes events: {}"
                     .format(events_file_name))

    def collect(self, node_ip_filter):
        log.info("collecting kubernetes version info ...")
        self.collect_k8s_version_info()
        log.info("collecting Kubernetes events JSON ...")
        self.collect_k8s_events()
        log.info("collecting nodes overview ...")
        self.collect_nodes_overview()
        log.info("collecting pods overview ...")
        self.collect_pods_overview()
        log.info("collecting pods summary ...")
        self.collect_pods_summary()
        log.info("collecting services overview ...")
        self.collect_services_overview()
        log.info("collecting cilium gops stats ...")
        self.collect_gops_stats(self.cilium_labels, node_ip_filter)
        log.info("collecting hubble gops stats ...")
        self.collect_gops_stats(self.hubble_labels, node_ip_filter)
        log.info("collecting kubernetes network policy ...")
        self.collect_netpol()
        log.info("collecting cilium network policy ...")
        self.collect_cnp()
        log.info("collecting cilium etcd secret ...")
        self.collect_cilium_secret()
        log.info("collecting cilium endpoints ...")
        self.collect_cep()
        log.info("collecting cilium daemonset yaml ...")
        self.collect_daemonset_yaml(name="cilium")
        log.info("collecting hubble daemonset yaml ...")
        self.collect_daemonset_yaml(name="hubble")
        log.info("collecting cilium configmap yaml ...")
        self.collect_cilium_configmap()
        if self.is_quick_mode:
            return
        # Time-consuming collect actions go here.
        log.info("collecting cilium-bugtool output ...")
        self.collect_cilium_bugtool_output(self.cilium_labels, node_ip_filter)
        log.info("collecting cilium logs ...")
        self.collect_logs(self.cilium_labels, node_ip_filter)
        self.collect_logs("io.cilium/app=operator", [])
        log.info("collecting hubble logs ...")
        self.collect_logs(self.hubble_labels, node_ip_filter)

    def archive(self):
        filename = self.output or self.sysdump_dir_name
        archive_name = shutil.make_archive(filename, 'zip',
                                           self.sysdump_dir_name)
        log.info("deleting directory: {}".format(self.sysdump_dir_name))
        shutil.rmtree(self.sysdump_dir_name)
        log.info("the sysdump has been saved in the file {}."
                 .format(archive_name))
