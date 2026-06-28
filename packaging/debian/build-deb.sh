#!/bin/bash
# Build whydpi .deb from the repo root.  Designed for Debian/Ubuntu
# containers (see build-deb-podman.sh for a Podman wrapper that sets up
# an ephemeral builder image).
#
# Usage:  cd <repo-root> && packaging/debian/build-deb.sh
# Output: ../whydpi_<version>-<rev>_all.deb  (next to the repo root)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [ -d debian ]; then
    echo "ERROR: 'debian/' already exists at the repo root — aborting to"  \
         "avoid clobbering it.  This script materialises debian/ from"     \
         "packaging/debian/ only for the duration of the build."           >&2
    exit 1
fi

# Materialise debian/ from the packaging overlay
cp -r packaging/debian debian
chmod +x debian/rules

# Fetch upstream version from pyproject.toml
VERSION=$(python3 -c "
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib
print(tomllib.loads(open('pyproject.toml').read())['project']['version'])
")

cleanup() {
    rm -rf debian
    rm -f ../whydpi_${VERSION}.orig.tar.gz
}
trap cleanup EXIT

# Build an .orig.tar.gz next to the source tree (dpkg expects this layout).
# We include the current working tree (including uncommitted edits) so that
# CI / iterative development both work.  For release builds, run this on a
# clean checkout of the tag.
tar --exclude='.git' --exclude='debian' --exclude='packaging/debian/dist' \
    --exclude='__pycache__' --exclude='*.egg-info' \
    --transform "s,^\.,whydpi-${VERSION}," \
    -czf "../whydpi_${VERSION}.orig.tar.gz" .

# Build the package without signing (PPA upload signs later)
dpkg-buildpackage -us -uc -b

# Copy artifacts into a predictable location before trap cleanup
mkdir -p packaging/debian/dist
cp -f ../whydpi_${VERSION}-*_all.deb      packaging/debian/dist/ 2>/dev/null || true
cp -f ../whydpi_${VERSION}-*.buildinfo    packaging/debian/dist/ 2>/dev/null || true
cp -f ../whydpi_${VERSION}-*.changes      packaging/debian/dist/ 2>/dev/null || true

echo
echo "=== artifacts ==="
ls -la packaging/debian/dist/
