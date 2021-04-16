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

import argparse
import distutils.util
import logging
import os
import sys
import time

import defaults
import namespace
import sysdumpcollector
import utils
from _version import __version__

log = logging.getLogger(__name__)


def parse_comma_sep_list(arg_string):
    item_list = arg_string.split(',')
    item_list = [s.strip() for s in item_list if s]
    return item_list


def prompt(msg):
    if sys.version_info > (2, 7, 0) and sys.version_info < (3, 0, 0):
        # The following line is ignored from static analysis because it will
        # fail to compile on Python 3.x.
        return raw_input(msg)  # noqa
    else:
        return input(msg)


if __name__ == '__main__':
    if sys.version_info < (2, 7, 0):
        sys.stderr.write('You need python 2.7+ to run this script\n')
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Cluster diagnosis '
                                                 'tool.')

    # The "sysdump" argument is left in here for backwards compatibility.
    parser.add_argument('sysdump', type=str, nargs='?', help=argparse.SUPPRESS)
    parser.add_argument('--cilium-ns', type=str, default=defaults.cilium_ns,
                        help='specify the k8s namespace Cilium is running in')
    parser.add_argument('--hubble-ns', type=str, default=defaults.hubble_ns,
                        help='specify the k8s namespace Hubble is running in')
    parser.add_argument('--hubble-relay-ns', type=str,
                        default=defaults.hubble_relay_ns,
                        help='specify the k8s namespace Hubble-Relay is' +
                             ' running in')
    parser.add_argument('--cilium-labels',
                        help='labels of cilium pods running in '
                        'the cluster',
                        default=defaults.cilium_labels)
    parser.add_argument('--hubble-labels',
                        help='labels of hubble pods running in '
                        'the cluster',
                        default=defaults.hubble_labels)
    parser.add_argument('--hubble-relay-labels',
                        help='labels of hubble-relay pods running in '
                        'the cluster',
                        default=defaults.hubble_relay_labels)
    parser.add_argument('-v', '--version', required=False, action='store_true',
                        help='get the version of this tool')

    parser.add_argument('--nodes',
                        type=parse_comma_sep_list,
                        help='only return logs for particular '
                             'nodes specified by a comma '
                             'separated list of node IP '
                             'addresses or node names.',
                        default='')
    parser.add_argument('--since',
                        help='only return logs newer than a '
                             'relative duration like 5s, 2m, or'
                             ' 3h. Defaults to 0.',
                        default=defaults.since)
    parser.add_argument('--size-limit', type=int,
                        help='size limit (bytes) for the '
                             'collected logs. '
                             'Defaults to 1073741824 (1GB)',
                        default=defaults.size_limit)
    parser.add_argument('--output',
                        help='output filename without '
                             ' .zip extension')
    parser.add_argument('--quick', type=distutils.util.strtobool,
                        default=defaults.quick,
                        help='enable quick mode. Logs and '
                             'cilium bugtool output will'
                             ' not be collected'
                             ' Defaults to "false"')

    args = parser.parse_args()

    if args.version:
        print(__version__)
        sys.exit(0)

    # Automatically infer Cilium and Hubble namespace using Cilium and Hubble
    # daemonset's namespaces respectively
    # Fall back to the specified namespace in the input argument if it fails.
    try:
        status = utils.get_resource_status('pod', label=args.cilium_labels)
        namespace.cilium_ns = status[0]
    except RuntimeError:
        namespace.cilium_ns = args.cilium_ns
        pass

    try:
        status = utils.get_resource_status(
            'pod', label=args.hubble_labels, must_exist=False,
        )
        if status is None:
            namespace.hubble_ns = args.hubble_ns
        else:
            namespace.hubble_ns = status[0]
    except RuntimeError:
        namespace.hubble_ns = args.hubble_ns
        pass

    try:
        status = utils.get_resource_status(
            'pod', label=args.hubble_relay_labels, must_exist=False,
        )
        if status is None:
            namespace.hubble_relay_ns = args.hubble_relay_ns
        else:
            namespace.hubble_relay_ns = status[0]
    except RuntimeError:
        namespace.hubble_relay_ns = args.hubble_relay_ns
        pass

    log.debug('Fetching nodes to determine cluster size...')
    nodes = utils.get_nodes()
    if not nodes:
        log.error('No nodes found')
    if len(nodes) > 20 and (not args.nodes and
                            args.since == defaults.since and
                            args.size_limit == defaults.size_limit):
        log.warning((
            'Detected a large cluster (> 20) with {} nodes. Consider '
            'setting one or more of the following to decrease the size '
            'of the sysdump as many nodes will slow down the collection '
            'and increase the size of the resulting '
            'archive:\n'
        ).format(len(nodes)) +
            '  --nodes       (Nodes to collect from)          \n'
            '  --since       (How far back in time to collect)\n'
            '  --size-limit  (Size limit of Cilium logs)      \n'
        )

        choice = prompt('Continue [y/N] (default is N)? ').strip().lower()
        if not choice or choice == 'n':
            sys.exit(0)

    try:
        sysdump_dir_name = './cilium-sysdump-{}'\
            .format(time.strftime('%Y%m%d-%H%M%S'))
        if not os.path.exists(sysdump_dir_name):
            os.makedirs(sysdump_dir_name)
        sysdumpcollector = sysdumpcollector.SysdumpCollector(
            sysdump_dir_name,
            args.since,
            args.size_limit,
            args.output,
            args.quick,
            args.cilium_labels,
            args.hubble_labels,
            args.hubble_relay_labels)
        sysdumpcollector.collect(args.nodes)
        sysdumpcollector.archive()
        sys.exit(0)
    except AttributeError:
        log.exception('Fatal error in collecting sysdump')
        sys.exit(1)

    sys.exit(0)
