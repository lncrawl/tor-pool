#!/bin/sh
# Print the CHANGELOG.md section for a version, or fail if there is none.
#
# CHANGELOG.md is curated by hand and is the only place release notes exist, so
# this is what the release workflow publishes. Failing when a section is missing
# is the point: it is what stops a version shipping with nothing said about it.
#
# Usage: .github/release-notes.sh 0.2.0
set -eu

version="${1:-}"
if [ -z "$version" ]; then
	echo "usage: $0 <version>" >&2
	exit 2
fi
version="${version#v}"

changelog="$(dirname "$0")/../CHANGELOG.md"

# Stops at the next version heading, or at the link definitions in the footer —
# the oldest section runs into those, and they belong to the file rather than to
# any one release.
notes=$(awk -v version="$version" '
	$0 ~ "^## \\[" version "\\]" { found = 1; next }
	found && /^## / { exit }
	found && /^\[[^]]+\]:/ { exit }
	found { print }
' "$changelog")

if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
	echo "CHANGELOG.md has no '## [$version]' section — move [Unreleased] into it first." >&2
	exit 1
fi

# Trim the blank lines that sit either side of a section in the file.
printf '%s\n' "$notes" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;}' -e '/\n$/ba'
