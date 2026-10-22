#!/bin/sh
# Build a noarch .rpm. Needs rpm-build. Usage: packaging/build-rpm.sh [outdir]
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-"$here/dist"}
ver=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$here/fleetguard/__init__.py")
top=$(mktemp -d)
trap 'rm -rf "$top"' EXIT
mkdir -p "$top"/SOURCES "$top"/SPECS "$top"/BUILD "$top"/RPMS "$top"/SRPMS "$top/src/fleetguard-$ver"
cp -r "$here/fleetguard" "$here/plugins" "$here/packaging" "$here/README.md" "$here/LICENSE" "$top/src/fleetguard-$ver/"
find "$top/src" -name __pycache__ -prune -exec rm -rf {} +
tar -C "$top/src" -czf "$top/SOURCES/fleetguard-$ver.tar.gz" "fleetguard-$ver"
cp "$here/packaging/fleetguard.spec" "$top/SPECS/"
rpmbuild --define "_topdir $top" --define "fg_version $ver" -bb "$top/SPECS/fleetguard.spec" >/dev/null
mkdir -p "$out"
cp "$top"/RPMS/noarch/*.rpm "$out/"
ls "$out"/fleetguard-*.rpm
