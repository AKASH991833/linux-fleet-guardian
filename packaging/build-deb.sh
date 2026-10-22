#!/bin/sh
# Build a .deb with dpkg-deb. Usage: packaging/build-deb.sh [outdir]
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-"$here/dist"}
ver=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$here/fleetguard/__init__.py")
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
install -d "$stage/usr/lib/fleetguard" "$stage/usr/bin" "$stage/usr/share/fleetguard/plugins" \
  "$stage/usr/share/doc/fleetguard" "$stage/etc/fleetguard" "$stage/lib/systemd/system" "$stage/DEBIAN"
cp -r "$here/fleetguard" "$stage/usr/lib/fleetguard/"
find "$stage/usr/lib/fleetguard" -name __pycache__ -prune -exec rm -rf {} +
printf '#!/bin/sh\nPYTHONPATH=/usr/lib/fleetguard exec python3 -m fleetguard "$@"\n' > "$stage/usr/bin/fleetguard"
chmod 755 "$stage/usr/bin/fleetguard"
cp "$here"/plugins/*.json "$here"/plugins/*.py "$stage/usr/share/fleetguard/plugins/"
cp "$here/README.md" "$here/LICENSE" "$stage/usr/share/doc/fleetguard/"
cp "$here/packaging/fleetguard.service" "$stage/lib/systemd/system/"
cp "$here/packaging/inventory.ini" "$here/packaging/fleetguard.env" "$stage/etc/fleetguard/"
chmod 640 "$stage/etc/fleetguard/fleetguard.env"
cat > "$stage/DEBIAN/conffiles" <<CONF
/etc/fleetguard/inventory.ini
/etc/fleetguard/fleetguard.env
CONF
cat > "$stage/DEBIAN/control" <<CTL
Package: fleetguard
Version: $ver
Section: admin
Priority: optional
Architecture: all
Depends: python3 (>= 3.6)
Recommends: openssh-client
Maintainer: Akash Vishwakarma <noreply@users.noreply.github.com>
Homepage: https://github.com/AKASH991833/linux-fleet-guardian
Description: Audit, fix, back up and watch Linux fleets
 CIS-style checks, drift detection, reversible fixes with automatic rollback,
 backup restore-tests, DR drills, performance anomaly detection, incident
 timelines, a read-only web panel and Prometheus metrics. Standard library only.
CTL
mkdir -p "$out"
dpkg-deb --root-owner-group --build "$stage" "$out/fleetguard_${ver}_all.deb" >/dev/null
echo "$out/fleetguard_${ver}_all.deb"
