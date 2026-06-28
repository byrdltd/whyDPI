#!/bin/bash
# Build whydpi .rpm from a local source tarball.  Expected to run
# inside a Fedora container (see packaging/fedora/README.md for the
# Podman recipe).
#
# Usage:  packaging/fedora/build-rpm.sh
# Output: packaging/fedora/dist/whydpi-<version>-1.<dist>.noarch.rpm
set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

VERSION=$(python3 -c "
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib
print(tomllib.loads(open('pyproject.toml').read())['project']['version'])
")

TOPDIR="$(mktemp -d)"
trap 'rm -rf "$TOPDIR"' EXIT

mkdir -p "$TOPDIR"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Assemble the source tarball that Source0 references.  We exclude the
# packaging tree and VCS metadata to mirror a clean release tarball.
tar --exclude='.git' --exclude='debian' \
    --exclude='packaging/*/dist' --exclude='packaging/*/src' \
    --exclude='packaging/*/BUILD*' --exclude='packaging/*/SOURCES' \
    --exclude='__pycache__' --exclude='*.egg-info' \
    --transform "s,^\.,whyDPI-${VERSION}," \
    -czf "$TOPDIR/SOURCES/whydpi-${VERSION}.tar.gz" .

cp packaging/fedora/whydpi.spec "$TOPDIR/SPECS/"

rpmbuild --define "_topdir $TOPDIR" -bb "$TOPDIR/SPECS/whydpi.spec"

mkdir -p packaging/fedora/dist
find "$TOPDIR/RPMS" -name '*.rpm' -exec cp -v {} packaging/fedora/dist/ \;

echo
echo "=== artifacts ==="
ls -la packaging/fedora/dist/
