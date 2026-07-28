#!/bin/sh
# Validate a version and split it into the parts the image tags are built from.
#
# Output is `key=value` lines, ready to append to $GITHUB_OUTPUT. Shared by the
# release and the scheduled rebuild: both have to agree on which tags float and
# which one is the immutable pin, and a second copy of this parsing is how they
# would stop agreeing.
#
# Usage: .github/version-parts.sh 0.2.0
set -eu

version="${1:-}"
version="${version#v}"

# Semver, with an optional prerelease suffix. Anything else would produce image
# tags nobody can reason about.
if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
	echo "'$version' is not a semantic version (want 0.2.0 or 0.2.0-rc.1)" >&2
	exit 1
fi

major="${version%%.*}"
rest="${version#*.}"
minor="$major.${rest%%.*}"

prerelease=false
case "$version" in *-*) prerelease=true ;; esac

# A bare major tag is suppressed while it is 0: before 1.0 semver puts breaking
# changes on the minor, so a `0` tag would carry someone from 0.1.x straight into
# an incompatible 0.2.x.
floating_major=false
if [ "$prerelease" = false ] && [ "$major" != 0 ]; then
	floating_major=true
fi

# A prerelease moves no floating tag at all — pushing a release candidate onto
# everyone tracking `latest` is the failure this avoids.
floating=false
if [ "$prerelease" = false ]; then
	floating=true
fi

cat <<EOF
version=$version
major=$major
minor=$minor
prerelease=$prerelease
floating=$floating
floating_major=$floating_major
EOF
