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

import namespace


cilium_ns = namespace.cilium_ns
hubble_ns = namespace.hubble_ns
hubble_relay_ns = namespace.hubble_relay_ns
cilium_labels = 'k8s-app=cilium'
hubble_labels = 'k8s-app=hubble'
hubble_relay_labels = 'k8s-app=hubble-relay'
since = '0'
size_limit = 1 * 1024 * 1024 * 1024
quick = 'false'
