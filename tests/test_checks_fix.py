import os
import stat

from fleetguard import checks as C, remediate, scan
from fleetguard.scan import run_check
from fleetguard.transport import FakeTransport
from tests.helpers import SandboxCase

REG = C.builtin_registry()


class EvaluatorTests(SandboxCase):
    def test_sysctl_equals(self):
        chk = REG.get("NET-002")
        self.assertEqual(run_check(FakeTransport({"sysctl": "1\n"}), chk)["status"], C.PASS)
        self.assertEqual(run_check(FakeTransport({"sysctl": "0\n"}), chk)["status"], C.FAIL)
        self.assertEqual(run_check(FakeTransport({"sysctl": C.NA}), chk)["status"], C.SKIP)

    def test_registry_ids_unique_and_fixes_wellformed(self):
        ids = [c.id for c in REG.all()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 20)
        for c in REG.all():
            if c.fix:
                self.assertTrue(c.fix.files, c.id)
                self.assertTrue(c.fix.script, c.id)

    def test_evaluator_crash_is_an_error_not_a_crash(self):
        def boom(out):
            raise RuntimeError("bad plugin")
        chk = C.Check("T-1", "t", "low", "x", "true", boom)
        self.assertEqual(run_check(FakeTransport(), chk)["status"], C.ERROR)

    def test_mode_evaluator(self):
        ev = C.ev_mode(0o640, ("root:root", "root:shadow"))
        self.assertEqual(ev("640 root:shadow\n")[0], C.PASS)
        self.assertEqual(ev("644 root:root\n")[0], C.FAIL)
        self.assertEqual(ev("600 bob:bob\n")[0], C.FAIL)
        self.assertEqual(ev(C.NA)[0], C.SKIP)


class SandboxFixTests(SandboxCase):
    def scan(self, *ids):
        return scan.scan_host(self.host, REG.select(ids=list(ids)))

    def test_ssh_fix_and_manual_rollback(self):
        original = "Port 22\n#PermitRootLogin prohibit-password\nUsePAM yes\n"
        self.write("etc/ssh/sshd_config", original, 0o600)
        self.assertEqual(self.scan("SSH-001")["results"][0]["status"], C.FAIL)
        res = remediate.apply_fix(self.host, REG.get("SSH-001"), self.store)
        self.assertEqual(res["outcome"], "fixed", res)
        self.assertIn("PermitRootLogin no", self.read("etc/ssh/sshd_config"))
        self.assertEqual(self.scan("SSH-001")["results"][0]["status"], C.PASS)
        rb = remediate.rollback(self.host, res["journal"], self.store)
        self.assertEqual(rb["outcome"], "rolled-back")
        self.assertEqual(self.read("etc/ssh/sshd_config"), original)
        self.assertEqual(oct(os.stat(os.path.join(self.root, "etc/ssh/sshd_config")).st_mode & 0o777), "0o600")
        self.assertEqual(remediate.rollback(self.host, res["journal"], self.store)["outcome"], "already-rolled-back")

    def test_fix_that_cannot_verify_is_rolled_back_automatically(self):
        # A drop-in overrides the main file (drop-ins are read first), so editing sshd_config
        # cannot make the check pass. Guardian must undo its own edit.
        original = "PermitRootLogin yes\n"
        self.write("etc/ssh/sshd_config", original, 0o600)
        self.write("etc/ssh/sshd_config.d/10-override.conf", "PermitRootLogin yes\n")
        res = remediate.apply_fix(self.host, REG.get("SSH-001"), self.store)
        self.assertEqual(res["outcome"], "rolled-back", res)
        self.assertEqual(self.read("etc/ssh/sshd_config"), original)
        entry = self.store.read_json("journal/%s.json" % res["journal"])
        self.assertEqual(entry["state"], "auto-rolled-back")

    def test_failing_script_is_rolled_back(self):
        self.write("etc/ssh/sshd_config", "PermitRootLogin yes\n", 0o600)
        chk = C.Check("T-2", "t", "low", "x", "echo no", C.ev_equals("yes"),
                      fix=C.Fix("break", ["/etc/ssh/sshd_config"],
                                'echo garbage > "$FG_ROOT/etc/ssh/sshd_config"; exit 1'))
        res = remediate.apply_fix(self.host, chk, self.store)
        self.assertEqual(res["outcome"], "rolled-back")
        self.assertEqual(self.read("etc/ssh/sshd_config"), "PermitRootLogin yes\n")

    def test_risky_fix_needs_flag(self):
        self.write("etc/ssh/sshd_config", "PasswordAuthentication yes\n", 0o600)
        res = remediate.apply_fix(self.host, REG.get("SSH-004"), self.store)
        self.assertEqual(res["outcome"], "skipped")
        self.assertIn("yes", self.read("etc/ssh/sshd_config"))
        res = remediate.apply_fix(self.host, REG.get("SSH-004"), self.store, allow_risky=True)
        self.assertEqual(res["outcome"], "fixed", res)

    def test_file_mode_fix_creates_file_snapshot_and_restores_mode(self):
        import grp, pwd
        owner = "%s:%s" % (pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name)
        chk = C.mode_check("T-FS", "shadow mode", "/etc/shadow", 0o640, (owner,), "high", "t")
        self.write("etc/shadow", "root:*:1:0:99999:7:::\n", 0o644)
        self.assertEqual(scan.scan_host(self.host, [chk])["results"][0]["status"], C.FAIL)
        res = remediate.apply_fix(self.host, chk, self.store)
        self.assertEqual(res["outcome"], "fixed", res)
        mode = stat.S_IMODE(os.stat(os.path.join(self.root, "etc/shadow")).st_mode)
        self.assertEqual(mode, 0o640)
        remediate.rollback(self.host, res["journal"], self.store)
        mode = stat.S_IMODE(os.stat(os.path.join(self.root, "etc/shadow")).st_mode)
        self.assertEqual(mode, 0o644)

    def test_new_file_is_removed_on_rollback(self):
        self.assertFalse(os.path.exists(os.path.join(self.root, "etc/login.defs")))
        self.write("etc/login.defs", "PASS_MAX_DAYS 99999\n")
        res = remediate.apply_fix(self.host, REG.get("ACC-004"), self.store)
        self.assertEqual(res["outcome"], "fixed", res)
        self.assertIn("PASS_MAX_DAYS   365", self.read("etc/login.defs"))
        remediate.rollback(self.host, res["journal"], self.store)
        self.assertEqual(self.read("etc/login.defs"), "PASS_MAX_DAYS 99999\n")

    def test_account_checks(self):
        self.write("etc/passwd", "root:x:0:0::/root:/bin/sh\nevil:x:0:0::/:/bin/sh\na:x:5:5::/:/bin/sh\nb:x:5:5::/:/bin/sh\n")
        self.write("etc/shadow", "root:!:1::::::\nbob::1::::::\n", 0o640)
        rep = self.scan("ACC-001", "ACC-002", "ACC-003")
        st = {r["id"]: r for r in rep["results"]}
        self.assertEqual(st["ACC-001"]["status"], C.FAIL)
        self.assertIn("bob", st["ACC-001"]["observed"])
        self.assertIn("evil", st["ACC-002"]["observed"])
        self.assertEqual(st["ACC-003"]["status"], C.FAIL)

    def test_drift_detection(self):
        self.write("etc/ssh/sshd_config", "PermitRootLogin no\n", 0o600)
        base = self.scan("SSH-001")
        scan.save_baseline(self.store, base)
        self.write("etc/ssh/sshd_config", "PermitRootLogin yes\n", 0o600)
        now = self.scan("SSH-001")
        drift = scan.drift_against_baseline(self.store, now)
        self.assertEqual([d["kind"] for d in drift], ["regressed"])
        self.assertEqual(scan.drift_against_baseline(self.store, base), [])

    def test_scan_fleet_records_events_and_drift(self):
        self.write("etc/ssh/sshd_config", "PermitRootLogin no\n", 0o600)
        chk = REG.select(ids=["SSH-001"])
        scan.scan_fleet([self.host], chk, self.store)
        self.write("etc/ssh/sshd_config", "PermitRootLogin yes\n", 0o600)
        scan.scan_fleet([self.host], chk, self.store)
        kinds = [e["kind"] for e in self.store.read_jsonl("events.jsonl")]
        self.assertIn("drift", kinds)
        self.assertEqual(kinds.count("scan"), 2)
