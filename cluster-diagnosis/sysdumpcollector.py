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

import logging
import re
import shutil
import subprocess
import utils
import datetime
import time


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
            sysdump_dir_name, since, size_limit):
        self.sysdump_dir_name = sysdump_dir_name
        self.since = since
        self.size_limit = size_limit

    def collect_nodes_overview(self):
        nodes_overview_file_name = "nodes-{}.json".format(datetime.datetime.
                                                          utcnow().isoformat())
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
        pods_overview_file_name = "pods-{}.json".format(datetime.datetime.
                                                        utcnow().isoformat())
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
        pods_summary_file_name = "pods-{}.txt".format(datetime.datetime.
                                                      utcnow().isoformat())
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

    def collect_logs(self, pod_name_prefix):
        for name, _, _, _ in \
                utils.get_pods_status_iterator(pod_name_prefix):
            log_file_name = "{}-{}".format(name,
                                           datetime.datetime.
                                           utcnow().isoformat())
            command = "kubectl logs {} --timestamps=true --since={} " \
                "--limit-bytes={} -n kube-system {} > {}/{}.log"
            cmd = command.format(
                "", self.since, self.size_limit, name,
                self.sysdump_dir_name, log_file_name)
            try:
                subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 0:
                    log.error("Error: {}. Could not collect log file: {}"
                              .format(exc, log_file_name))
            else:
                log.info("collected log file: {}".format(log_file_name))

            # Previous containers
            log_file_name_previous = "{0}-previous".format(log_file_name)
            cmd = command.format(
                "--previous", self.since, self.size_limit, name,
                self.sysdump_dir_name, log_file_name_previous)
            try:
                subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 0:
                    log.debug(
                        "Debug: {}. Could not collect previous "
                        "log for '{}': {}"
                        .format(exc, name, log_file_name))
            else:
                log.info("collected log file: {}".format(
                    log_file_name_previous))

    def collect_gops_stats(self, pod_name_prefix):
        self.collect_gops(pod_name_prefix, "stats")
        self.collect_gops(pod_name_prefix, "memstats")
        self.collect_gops(pod_name_prefix, "stack")

    def collect_gops(self, pod_name_prefix, type_of_stat):
        for name, _, _, _ in \
                utils.get_pods_status_iterator(pod_name_prefix):
            file_name = "{}-{}-{}.txt".format(name,
                                              datetime.datetime.
                                              utcnow().isoformat(),
                                              type_of_stat)
            cmd = "kubectl exec -it -n kube-system {} -- " \
                  "/bin/gops {} 1 > {}/{}".format(
                      name, type_of_stat, self.sysdump_dir_name, file_name)
            try:
                subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 0:
                    log.error("Error: {}. Could not collect gops {}: {}"
                              .format(exc, type_of_stat, file_name))
            else:
                log.info("collected gops {} file: {}".format(
                    type_of_stat, file_name))

    def collect_cnp(self):
        cnp_file_name = "cnp-{}.yaml".format(datetime.datetime.
                                             utcnow().isoformat())
        cmd = "kubectl get cnp -o yaml --all-namespaces > {}/{}".format(
              self.sysdump_dir_name, cnp_file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Could not collect cilium network "
                          "policy: {}".format(exc, cnp_file_name))
        else:
            log.info("collected cilium network policy: {}"
                     .format(cnp_file_name))

    def collect_daemonset_yaml(self):
        daemonset_file_name = "cilium-ds-{}.yaml".format(datetime.datetime
                                                         .utcnow().isoformat())
        cmd = "kubectl get ds cilium -n kube-system -oyaml > {}/{}".format(
            self.sysdump_dir_name, daemonset_file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Unable to get cilium daemonset yaml")
        else:
            log.info("collected cilium daemonset yaml file: {}".format(
                daemonset_file_name))

    def collect_cilium_configmap(self):
        configmap_file_name = "cilium-configmap-{}.yaml".format(
            datetime.datetime.utcnow().isoformat())
        cmd = "kubectl get configmap cilium-config -n kube-system -oyaml " \
              "> {}/{}".format(self.sysdump_dir_name, configmap_file_name)
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError as exc:
            if exc.returncode != 0:
                log.error("Error: {}. Unable to get cilium configmap yaml")
        else:
            log.info("collected cilium configmap yaml file: {}".format(
                configmap_file_name))

    def collect_cilium_bugtool_output(self):
        for name, _, _, _ in \
                utils.get_pods_status_iterator("cilium-"):
            bugtool_output_file_name = "bugtool-{}-{}.tar".format(
                name, time.strftime("%Y%m%d-%H%M%S"))
            cmd = "kubectl exec -n kube-system -it {} cilium-bugtool".format(
                name)
            try:
                encoded_output = subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError as exc:
                if exc.returncode != 0:
                    log.error(
                        "Error: {}. Could not run cilium-bugtool on {}"
                        .format(exc, name))
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
                        "Error: {}. Could not find cilium-bugtool output"
                        " file name".format(exc))

                cmd = "kubectl cp kube-system/{}:{} ./{}/{}".format(
                    name, output_file_name, self.sysdump_dir_name,
                    bugtool_output_file_name)
                try:
                    subprocess.check_output(cmd, shell=True)
                except subprocess.CalledProcessError as exc:
                    if exc.returncode != 0:
                        log.error(
                            "Error: {} Could not collect cilium-bugtool"
                            " output: {}".format(
                                exc, bugtool_output_file_name))
                else:
                    log.info("collected cilium-bugtool output: {}".format(
                        bugtool_output_file_name))

    def collect(self):
        log.info("collecting nodes overview ...")
        self.collect_nodes_overview()
        log.info("collecting pods overview ...")
        self.collect_pods_overview()
        log.info("collecting pods summary ...")
        self.collect_pods_summary()
        log.info("collecting cilium gops stats ...")
        self.collect_gops_stats("cilium-")
        log.info("collecting cilium network policy ...")
        self.collect_cnp()
        log.info("collecting cilium daemonset yaml ...")
        self.collect_daemonset_yaml()
        log.info("collecting cilium configmap yaml ...")
        self.collect_cilium_configmap()
        log.info("collecting cilium-bugtool output ...")
        self.collect_cilium_bugtool_output()
        log.info("collecting cilium logs ...")
        self.collect_logs("cilium-")

    def archive(self):
        shutil.make_archive(self.sysdump_dir_name, 'zip',
                            self.sysdump_dir_name)
        log.info("deleting directory: {}".format(self.sysdump_dir_name))
        shutil.rmtree(self.sysdump_dir_name)
        log.info("the sysdump has been saved in the file {}.zip."
                 .format(self.sysdump_dir_name))
