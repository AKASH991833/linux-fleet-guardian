#!/bin/sh
# Runs inside a distro container as root. Installs deps, then exercises Guardian on the REAL system:
# unit tests, a live scan, a real fix + rollback of /etc/ssh/sshd_config (validated by the real sshd),
# and a backup restore-test plus DR drill.
set -eu
cd "$(dirname "$0")/.."

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq python3 openssh-server iproute2 >/dev/null
  mkdir -p /run/sshd
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q python3 openssh-server iproute >/dev/null
elif command -v microdnf >/dev/null 2>&1; then
  microdnf install -y python3 openssh-server iproute >/dev/null
else
  echo "no supported package manager" >&2; exit 1
fi
python3 --version
echo "== unit tests"
python3 -m unittest discover -s tests -t . 2>&1 | tail -4

echo "== live scan"
export FLEETGUARD_STATE=$(mktemp -d)
python3 -m fleetguard scan --format json -o /tmp/scan.json >/dev/null
python3 - <<'PY'
import json
rep = json.load(open("/tmp/scan.json"))[0]
assert rep["reachable"], "scan did not reach local host"
assert len(rep["results"]) >= 20
errors = [r for r in rep["results"] if r["status"] == "ERROR"]
assert not errors, errors
print("live scan ok: score", rep["score"], rep["summary"])
PY

echo "== real fix + rollback against sshd"
ssh-keygen -A >/dev/null 2>&1
cfg=/etc/ssh/sshd_config
[ -f "$cfg" ] || touch "$cfg"
# make the starting state explicit and unambiguous (drop-ins can override the main file)
rm -f /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
sed -i -E '/^[[:space:]]*#?[[:space:]]*PermitRootLogin[[:space:]]/d' "$cfg"
echo "PermitRootLogin yes" >> "$cfg"
chmod 600 "$cfg"
cp -p "$cfg" /tmp/sshd_config.orig
python3 -m fleetguard fix --check SSH-001 | grep -q 'PLAN SSH-001'
grep -q 'PermitRootLogin yes' "$cfg"            # dry run changed nothing
python3 -m fleetguard fix --check SSH-001 --apply
grep -q '^PermitRootLogin no' "$cfg"
sshd -t -f "$cfg"                                # real sshd accepts the result
python3 -m fleetguard scan --check SSH-001 | grep -q 'score 100.0'
jid=$(python3 -m fleetguard rollback --list | awk '{print $1}' | tail -1)
python3 -m fleetguard rollback "$jid"
cmp "$cfg" /tmp/sshd_config.orig                  # byte-identical after rollback
echo "fix + rollback verified on real sshd_config"

echo "== backup restore-test and DR drill"
mkdir -p /tmp/data/sub && echo hello > /tmp/data/a && head -c 100000 /dev/urandom > /tmp/data/sub/b
python3 -m fleetguard backup run --source /tmp/data --dest /tmp/bk --name ci >/dev/null
python3 -m fleetguard backup restore-test --dest /tmp/bk --rpo 600 --rto 60 | grep -q '"ok": true'
python3 -m fleetguard drill --source /tmp/data --report /tmp/drill.md
grep -q 'PASS' /tmp/drill.md
echo "== timeline"
python3 -m fleetguard timeline | grep -q 'fix'
echo "ALL OK"
