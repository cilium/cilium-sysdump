 # Copyright 2017-2020 Authors of Cilium
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 #     http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.

.PHONY: build

check: check-tools
	pycodestyle .

check-tools:
	command -v pycodestyle >/dev/null 2>&1 || { echo "Package pycodestyle not installed. Aborting." >&2; exit 1; }

version:
	echo "__version__ = \"$(shell cat VERSION)-$(shell git log --pretty=format:'%h' -n 1 2>/dev/null || echo "unknown")\"" > cluster-diagnosis/_version.py

build: syntax-check clean check version
	cd cluster-diagnosis/ && zip -r ../cluster-diagnosis.zip *

syntax-check:
	./python-syntax-check.sh cluster-diagnosis

clean:
	rm -rf ./cluster-diagnosis/*.pyc ./cluster-diagnosis/__pycache__ ./cluster-diagnosis/_version.py
	rm -rf ./cluster-diagnosis.zip

release: build
	./release.sh
