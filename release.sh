#!/bin/bash
#
# release.sh
#
# Intended to be called via "make release". Uses the current state of GitHub
# releases and the VERSION file to determine the previous and next releases
# of this tool, and instructs the maintainer how to prepare the release.

RELEASE_BASE_URL="https://github.com/cilium/cilium-sysdump/releases"
LATEST_RELEASE_URL="$RELEASE_BASE_URL/latest"
CREATE_RELEASE_URL="$RELEASE_BASE_URL/new"
NEXT_RELEASE="v$(cat VERSION)"

set -eo pipefail

PREVIOUS_RELEASE=$(curl "$LATEST_RELEASE_URL" --max-time 5 -s -o/dev/null -w '%{redirect_url}' \
	| sed 's/^.*\(v[0-9]\+[.][0-9]\+[.]\?[0-9]*\)$/\1/')
echo "Preparing release $NEXT_RELEASE. Release notes since $PREVIOUS_RELEASE:"
echo; echo "## Summary"
echo; echo "<Write a brief summary here>"
echo; echo "## Changes"
git shortlog "$PREVIOUS_RELEASE"..
echo; echo "Next steps:"
echo "1) Create release at $CREATE_RELEASE_URL"
echo "2) Upload the freshly compiled cilium-sysdump.zip from this directory"
echo "3) Make the release using release notes above"
echo "4) Update VERSION"
echo "5) Submit version bump PR"
