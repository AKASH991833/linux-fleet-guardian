"""Build a demo state directory from throw-away sandbox trees (no real hosts involved).

    python3 examples/make_demo.py /tmp/fg-demo
    FLEETGUARD_STATE=/tmp/fg-demo python3 -m fleetguard serve

Three fake hosts get different configs; Guardian scans them, one host drifts, one gets fixed,
and a synthetic performance history with one spike is recorded. All data is synthetic.
"""
import os
import random
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fleetguard import checks as C, inventory, perf, remediate, scan  # noqa: E402
from fleetguard.store import Store  # noqa: E402

GOOD_SSH = "PermitRootLogin no\nPermitEmptyPasswords no\nX11Forwarding no\nPasswordAuthentication no\nMaxAuthTries 3\n"
BAD_SSH = "PermitRootLogin yes\nPermitEmptyPasswords no\nX11Forwarding yes\nPasswordAuthentication yes\nMaxAuthTries 6\n"


def mkhost(name, ssh, shadow_mode, passwd_extra=""):
    root = tempfile.mkdtemp(prefix="fg-demo-%s-" % name)
    for rel, text, mode in [
        ("etc/ssh/sshd_config", ssh, 0o600),
        ("etc/passwd", "root:x:0:0::/root:/bin/sh\nops:x:1000:1000::/home/ops:/bin/sh\n" + passwd_extra, 0o644),
        ("etc/shadow", "root:!:1::::::\nops:!:1::::::\n", shadow_mode),
        ("etc/group", "root:x:0:\n", 0o644),
        ("etc/gshadow", "root:!::\n", 0o640),
        ("etc/login.defs", "PASS_MAX_DAYS 99999\n", 0o644),
    ]:
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(text)
        os.chmod(p, mode)
    return root, inventory.Host(name, {"local": "true", "root": root})


def main(dest):
    store = Store(dest)
    import grp
    import pwd
    me = "%s:%s" % (pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name)
    full = C.builtin_registry()
    reg = C.Registry()
    # Demo trees are owned by whoever runs this script, so accept that owner; kernel checks are left
    # out because they would read the machine running the demo, not the fake hosts.
    for c in full.all():
        if c.id.startswith(("NET", "KRN", "SVC", "LOG")):
            continue
        if c.id.startswith("FS-"):
            path = {"FS-001": "/etc/passwd", "FS-002": "/etc/shadow", "FS-003": "/etc/group",
                    "FS-004": "/etc/gshadow", "FS-005": "/etc/ssh/sshd_config"}[c.id]
            mode = {"FS-001": 0o644, "FS-002": 0o640, "FS-003": 0o644, "FS-004": 0o640, "FS-005": 0o600}[c.id]
            c = C.mode_check(c.id, c.title, path, mode, (me,), c.severity, c.cis)
        reg.add(c)
    _, web1 = mkhost("web1", GOOD_SSH, 0o640)
    root2, db1 = mkhost("db1", GOOD_SSH, 0o640)
    _, legacy = mkhost("legacy-app", BAD_SSH, 0o644, "toor:x:0:0::/:/bin/sh\n")
    hosts = [web1, db1, legacy]
    scan.scan_fleet(hosts, reg.all(), store)
    for h in hosts:
        scan.save_baseline(store, scan.scan_host(h, reg.all()))
    # db1 drifts: someone re-enabled root login
    with open(os.path.join(root2, "etc/ssh/sshd_config"), "a") as fh:
        fh.write("PermitRootLogin yes\n")
    with open(os.path.join(root2, "etc/ssh/sshd_config")) as fh:
        text = fh.read().replace("PermitRootLogin no\n", "")
    open(os.path.join(root2, "etc/ssh/sshd_config"), "w").write(text)
    scan.scan_fleet(hosts, reg.all(), store)
    # legacy-app: apply a safe fix
    remediate.apply_fix(legacy, reg.get("SSH-001"), store)
    remediate.apply_fix(legacy, reg.get("FS-002"), store)
    scan.scan_fleet(hosts, reg.all(), store)
    # synthetic perf history with a spike on the last sample
    random.seed(7)
    t0 = time.time() - 3600 * 3
    for name in ("web1", "db1", "legacy-app"):
        for i in range(60):
            s = {"ts": t0 + i * 180, "load_per_cpu": round(0.3 + random.random() * 0.1, 3),
                 "mem_used_pct": round(46 + random.random() * 3, 2), "swap_used_pct": 0.0, "disk_used_pct": 41.0}
            if name == "db1" and i == 59:
                s["load_per_cpu"] = 3.4
            store.append_jsonl("perf/%s.jsonl" % name, s)
    hist = store.read_jsonl("perf/db1.jsonl")
    for a in perf.detect(hist[:-1], hist[-1]):
        store.event("anomaly", "db1", "%s=%s vs baseline median %s (robust z %s)" % (
            a["metric"], a["value"], a["baseline_median"], a["robust_z"]), "high", metric=a["metric"])
    print("demo state written to", dest)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/fg-demo")
