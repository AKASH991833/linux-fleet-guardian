#!/bin/sh
# Ubuntu runner: scan a 2-host "fleet" over real SSH, fix over SSH with sudo, roll back, detect an unreachable host.
set -eu
cd "$(dirname "$0")/.."
sudo apt-get update -qq && sudo apt-get install -y -qq openssh-server >/dev/null
sudo mkdir -p /run/sshd
sudo ssh-keygen -A >/dev/null
sudo systemctl restart ssh || sudo /usr/sbin/sshd
KEY=$(mktemp -u)
ssh-keygen -q -t ed25519 -N '' -f "$KEY"
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cat "$KEY.pub" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
ssh-keyscan -H 127.0.0.1 >> ~/.ssh/known_hosts 2>/dev/null
INV=$(mktemp)
cat > "$INV" <<INI
[defaults]
user = $(id -un)
key = $KEY
sudo = true
[node-a]
address = 127.0.0.1
[node-b]
address = 127.0.0.1
[node-down]
address = 127.0.0.1
port = 1
INI
FLEETGUARD_STATE=$(mktemp -d)
export FLEETGUARD_STATE
set +e
python3 -m fleetguard scan -i "$INV" --format json -o /tmp/fleet.json
rc=$?
set -e
echo "scan exit code: $rc (3 expected: one host unreachable)"
[ "$rc" -eq 0 ] || [ "$rc" -eq 3 ] || { echo "unexpected exit code"; exit 1; }
python3 - <<'PY'
import json
reps = {r["host"]: r for r in json.load(open("/tmp/fleet.json"))}
assert reps["node-a"]["reachable"] and reps["node-b"]["reachable"], "SSH hosts not scanned"
assert not reps["node-down"]["reachable"], "dead host must be reported unreachable"
# sudo SSH transport should read /etc/shadow, so ACC-001 is evaluated, not skipped
acc = [r for r in reps["node-a"]["results"] if r["id"] == "ACC-001"][0]
assert acc["status"] in ("PASS", "FAIL"), acc
print("ssh fleet scan ok:", {h: r["score"] for h, r in reps.items()})
PY
echo "== fix + rollback over SSH on node-a"
sudo cp -p /etc/ssh/sshd_config /tmp/sshd_config.orig
sudo sed -i -E '/^[[:space:]]*#?[[:space:]]*X11Forwarding[[:space:]]/d' /etc/ssh/sshd_config
echo "X11Forwarding yes" | sudo tee -a /etc/ssh/sshd_config >/dev/null
sudo rm -f /etc/ssh/sshd_config.d/*x11* 2>/dev/null || true
python3 -m fleetguard fix -i "$INV" --limit node-a --check SSH-003 --apply
sudo grep -q '^X11Forwarding no' /etc/ssh/sshd_config
sudo sshd -t
JID=$(python3 -m fleetguard rollback --list | awk '$2=="node-a"{print $1}' | tail -1)
python3 -m fleetguard rollback -i "$INV" --host node-a "$JID"
echo "ok: fix and rollback over SSH"
