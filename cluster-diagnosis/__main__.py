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

import utils
import ciliumchecks
import k8schecks
import logging
import sys
import argparse
import sysdumpcollector
import os
import time


log = logging.getLogger(__name__)
exit_code = 0


if __name__ == "__main__":
    if sys.version_info < (2, 7, 0):
        sys.stderr.write("You need python 2.7+ to run this script\n")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Cluster diagnosis '
                                                 'tool.')
    # Add an optional subparser for the sysdump command.
    # Optional subparsers are only supported in Python 3.3+.
    # Python 2.7 optional subparsers implementation has bugs,
    # which have not been fixed/backported.
    # To workaround the optional subparser bug, parse the args only if
    # one of the supported commands is present.
    if '-h' in sys.argv or '--help' in sys.argv or 'sysdump' in sys.argv:
        subparsers = parser.add_subparsers(dest='sysdump')
        subparsers.required = False
        parser_sysdump = subparsers.add_parser('sysdump',
                                               help='collect logs and other '
                                                    'useful information')
        parser_sysdump.add_argument('--since',
                                    help='Only return logs newer than a '
                                         'relative duration like 5s, 2m, or'
                                         ' 3h. Defaults to all logs.',
                                    default='12h')
        parser_sysdump.add_argument('--size-limit', type=int,
                                    help='size limit (bytes) for the '
                                         'collected logs',
                                    default=256 * 1024 * 1024)

    args = parser.parse_args()
    try:
        if args.sysdump:
            sysdump_dir_name = "./cilium-sysdump-{}"\
                .format(time.strftime("%Y%m%d-%H%M%S"))
            if not os.path.exists(sysdump_dir_name):
                os.makedirs(sysdump_dir_name)
            sysdumpcollector = sysdumpcollector.SysdumpCollector(
                sysdump_dir_name,
                args.since,
                args.size_limit)
            sysdumpcollector.collect()
            sys.exit(0)
    except AttributeError:
        pass
    nodes = utils.get_nodes()

    k8s_check_grp = utils.ModuleCheckGroup("k8s")
    k8s_check_grp.add(
        utils.ModuleCheck(
            "check the kube-apiserver version",
            lambda: k8schecks.check_kube_apiserver_version_cb()))
    k8s_check_grp.add(
        utils.ModuleCheck(
            "check RBAC configuration",
            lambda: k8schecks.check_rbac_cb()))
    if not k8s_check_grp.run():
        exit_code = 1

    cilium_check_grp = utils.ModuleCheckGroup("cilium")
    cilium_check_grp.add(
        utils.ModuleCheck(
            "check whether pod is running",
            lambda: ciliumchecks.check_pod_running_cb(nodes)))
    cilium_check_grp.add(
        utils.ModuleCheck(
            "check the access log parameter",
            lambda: ciliumchecks.check_access_log_config_cb()))
    cilium_check_grp.add(utils.ModuleCheck(
        "L3/4 visibility: check whether DropNotification is enabled",
        lambda: ciliumchecks.check_drop_notifications_enabled_cb()))
    cilium_check_grp.add(utils.ModuleCheck(
        "L3/4 visibility: check whether TraceNotification is enabled",
        lambda: ciliumchecks.check_trace_notifications_enabled_cb()))

    if not cilium_check_grp.run():
        exit_code = 1

    sys.exit(exit_code)
