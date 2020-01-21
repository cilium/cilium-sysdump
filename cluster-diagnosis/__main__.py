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

from _version import __version__
import utils
import ciliumchecks
import k8schecks
import namespace
import logging
import sys
import argparse
import sysdumpcollector
import os
import time
import distutils.util

log = logging.getLogger(__name__)
exit_code = 0


def parse_comma_sep_list(arg_string):
    item_list = arg_string.split(',')
    item_list = [s.strip() for s in item_list if len(s)]
    return item_list


if __name__ == "__main__":
    if sys.version_info < (2, 7, 0):
        sys.stderr.write("You need python 2.7+ to run this script\n")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Cluster diagnosis '
                                                 'tool.')

    parser.add_argument('--cilium-ns', type=str, default='kube-system',
                        help="specify k8s namespace Cilium is running in")
    parser.add_argument('--cilium-labels',
                        help='Labels of cilium pods running in '
                        'the cluster',
                        default="k8s-app=cilium")
    parser.add_argument('-v', '--version', required=False, action='store_true',
                        help="get the version of this tool")
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
                                               help='Collect logs and other '
                                                    'useful information.')
        parser_sysdump.add_argument('--nodes',
                                    type=parse_comma_sep_list,
                                    help='Only return logs for particular '
                                         'nodes specified by a comma '
                                         'separated list of node IP '
                                         'addresses.',
                                    default="")
        parser_sysdump.add_argument('--since',
                                    help='Only return logs newer than a '
                                         'relative duration like 5s, 2m, or'
                                         ' 3h. Defaults to 30m.',
                                    default='30m')
        parser_sysdump.add_argument('--size-limit', type=int,
                                    help='size limit (bytes) for the '
                                         'collected logs. '
                                         'Defaults to 1048576 (1MB).',
                                    default=1 * 1024 * 1024)
        parser_sysdump.add_argument('--output',
                                    help='Output filename without '
                                         ' .zip extension')
        parser_sysdump.add_argument('--quick', type=distutils.util.strtobool,
                                    default="false",
                                    help='Enable quick mode. Logs and '
                                         'cilium bugtool output will'
                                         ' not be collected.'
                                         'Defaults to "false".')

    args = parser.parse_args()

    if args.version:
        print(__version__)
        sys.exit(0)

    # Automatically infer Cilium's namespace using Cilium daemonset's namespace
    # Fall back to the specified namespace in the input argument if it fails.
    try:
        status = utils.get_resource_status(
            "pod", full_name="", label=args.cilium_labels)
        namespace.cilium_ns = status[0]
    except RuntimeError as e:
        namespace.cilium_ns = args.cilium_ns
        pass
    try:
        if args.sysdump:
            sysdump_dir_name = "./cilium-sysdump-{}"\
                .format(time.strftime("%Y%m%d-%H%M%S"))
            if not os.path.exists(sysdump_dir_name):
                os.makedirs(sysdump_dir_name)
            sysdumpcollector = sysdumpcollector.SysdumpCollector(
                sysdump_dir_name,
                args.since,
                args.size_limit,
                args.output,
                args.quick,
                args.cilium_labels)
            sysdumpcollector.collect(args.nodes)
            sysdumpcollector.archive()
            sys.exit(0)
    except AttributeError as e:
        error_string = str(e)
        # This change makes sure we *only* ignore attribute
        # exceptions related to the args.sysdump workaround.
        if (error_string.find('sysdump') != -1):
            pass
        else:
            log.exception("Fatal error in collecting sysdump")
            sys.exit(1)
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
            "check whether cilium version is supported",
            lambda: ciliumchecks.check_cilium_version_cb(args.cilium_labels)))
    cilium_check_grp.add(
        utils.ModuleCheck(
            "check whether pod is running",
            lambda: ciliumchecks.check_pod_running_cb(nodes,
                                                      args.cilium_labels)))
    cilium_check_grp.add(utils.ModuleCheck(
        "L3/4 visibility: check whether DropNotification is enabled",
        lambda: ciliumchecks.check_drop_notifications_enabled_cb(
            args.cilium_labels)))
    cilium_check_grp.add(utils.ModuleCheck(
        "L3/4 visibility: check whether TraceNotification is enabled",
        lambda: ciliumchecks.check_trace_notifications_enabled_cb(
            args.cilium_labels)))

    if not cilium_check_grp.run():
        exit_code = 1

    sys.exit(exit_code)
