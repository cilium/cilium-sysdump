#!/usr/bin/env python
# Copyright 2020 Authors of Cilium
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

import socket


def is_ipv4(s):
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except (TypeError, socket.error):
        pass
    return False


def is_ipv6(s):
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except (TypeError, socket.error):
        pass
    return False


def is_ipaddress(s):
    return is_ipv4(s) or is_ipv6(s)
