#!/bin/sh
# Converge the role twice (second run must change nothing) and check the live service.
set -eu
cd "$(dirname "$0")/../ansible"
python3 -m pip install -q ansible-core
echo "localhost ansible_connection=local" > /tmp/ansible-inv
ansible-playbook -i /tmp/ansible-inv site.yml | tee /tmp/run1.log
ansible-playbook -i /tmp/ansible-inv site.yml | tee /tmp/run2.log
grep -Eq 'changed=0 .*failed=0' /tmp/run2.log || { echo "role is not idempotent"; exit 1; }
systemctl is-active fleetguard
for _ in 1 2 3 4 5 6 7 8 9 10; do curl -fs http://127.0.0.1:9877/healthz && break; sleep 1; done
curl -fs http://127.0.0.1:9877/metrics | grep -q fleetguard_
echo "ansible role converged, idempotent, service answering"
