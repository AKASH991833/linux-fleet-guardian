import json
import os
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from fleetguard import checks as C, cli, inventory, plugins, report, scan, timeline, web
from tests.helpers import SandboxCase


class PluginTests(SandboxCase):
    def test_declarative_plugin(self):
        pd = tempfile.mkdtemp()
        json.dump([{"id": "CUS-001", "title": "banner enabled", "file": "/etc/motd.conf",
                    "regex": "^banner=on", "expect": "present"}], open(os.path.join(pd, "a.json"), "w"))
        reg = C.builtin_registry()
        self.assertEqual(plugins.load_dir(reg, pd), ["a.json"])
        self.write("etc/motd.conf", "banner=off\n")
        rep = scan.scan_host(self.host, reg.select(ids=["CUS-001"]))
        self.assertEqual(rep["results"][0]["status"], C.FAIL)
        self.write("etc/motd.conf", "banner=on\n")
        rep = scan.scan_host(self.host, reg.select(ids=["CUS-001"]))
        self.assertEqual(rep["results"][0]["status"], C.PASS)

    def test_regex_with_quote_is_safe(self):
        pd = tempfile.mkdtemp()
        json.dump({"id": "CUS-002", "title": "q", "file": "/etc/x", "regex": "^a'b"}, open(os.path.join(pd, "a.json"), "w"))
        reg = C.builtin_registry()
        plugins.load_dir(reg, pd)
        self.write("etc/x", "a'b\n")
        self.assertEqual(scan.scan_host(self.host, reg.select(ids=["CUS-002"]))["results"][0]["status"], C.PASS)

    def test_python_plugin_and_bad_plugin(self):
        pd = tempfile.mkdtemp()
        open(os.path.join(pd, "p.py"), "w").write(
            "def register(reg, api):\n"
            "    reg.add(api.Check('PY-001','py','low','Custom','echo ok',api.ev_equals('ok')))\n")
        reg = C.builtin_registry()
        plugins.load_dir(reg, pd)
        self.assertEqual(scan.scan_host(self.host, reg.select(ids=["PY-001"]))["results"][0]["status"], C.PASS)
        pd2 = tempfile.mkdtemp()
        json.dump({"id": "X"}, open(os.path.join(pd2, "bad.json"), "w"))
        with self.assertRaises(ValueError):
            plugins.load_dir(C.builtin_registry(), pd2)

    def test_example_plugins_load(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        reg = C.builtin_registry()
        self.assertTrue(plugins.load_dir(reg, os.path.join(here, "plugins")))


class InventoryTests(unittest.TestCase):
    def test_load(self):
        p = tempfile.mktemp()
        open(p, "w").write("[defaults]\nuser=ops\nsudo=true\n[web1]\naddress=10.0.0.1\n[me]\nlocal=true\n")
        hs = inventory.load(p)
        self.assertEqual([h.name for h in hs], ["web1", "me"])
        t = hs[0].transport()
        self.assertEqual(t.user, "ops")
        self.assertTrue(t.sudo)
        self.assertIn("ops@10.0.0.1", t._argv("true"))
        self.assertEqual(hs[1].transport().name, "me")

    def test_empty_inventory_rejected(self):
        p = tempfile.mktemp()
        open(p, "w").write("[defaults]\nuser=x\n")
        with self.assertRaises(ValueError):
            inventory.load(p)


class TimelineTests(SandboxCase):
    def test_auth_burst(self):
        log = tempfile.mktemp()
        lines = ["Oct 22 10:00:%02d host sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2" % i
                 for i in range(6)]
        lines += ["Oct 22 11:00:00 host sshd[1]: Failed password for bob from 198.51.100.2 port 22 ssh2",
                  "Oct 22 11:00:01 host sshd[1]: Accepted password for bob from 198.51.100.2"]
        open(log, "w").write("\n".join(lines))
        ev = timeline.parse_auth_log(log, year=2026)
        self.assertEqual(len(ev), 1)
        self.assertIn("203.0.113.5", ev[0]["message"])

    def test_render_escapes_html(self):
        ev = [{"ts": 1.0, "kind": "x", "host": "h", "severity": "high", "message": "<script>alert(1)</script>"}]
        self.assertNotIn("<script>", timeline.to_html(ev))
        self.assertIn("| h |", timeline.to_markdown(ev))

    def test_filters(self):
        ev = [{"ts": 1, "kind": "a", "host": "h1", "severity": "info", "message": "m"},
              {"ts": 100, "kind": "a", "host": "h2", "severity": "info", "message": "m"}]
        self.assertEqual(len(timeline.build(ev, since=50)), 1)
        self.assertEqual(len(timeline.build(ev, hosts=["h1"])), 1)


class ReportTests(SandboxCase):
    def test_formats(self):
        self.write("etc/ssh/sshd_config", "PermitRootLogin yes\n", 0o600)
        reps = [scan.scan_host(self.host, C.builtin_registry().select(ids=["SSH-001", "FS-005"]))]
        self.assertIn("SSH-001", report.to_text(reps))
        self.assertIn("| FAIL |", report.to_markdown(reps))
        self.assertIn("<failure", report.to_junit(reps))
        self.assertEqual(json.loads(report.to_json(reps))[0]["host"], "sandbox")


class WebTests(SandboxCase):
    def start(self, token=None):
        srv = web.HTTPServer(("127.0.0.1", 0), web.make_handler(self.store, token))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return "http://127.0.0.1:%d" % srv.server_port

    def populate(self):
        self.write("etc/ssh/sshd_config", "PermitRootLogin yes\n", 0o600)
        scan.scan_fleet([self.host], C.builtin_registry().select(ids=["SSH-001", "FS-005"]), self.store)

    def test_endpoints(self):
        self.populate()
        base = self.start()
        page = urlopen(base + "/").read().decode()
        self.assertIn("Linux Fleet Guardian", page)
        self.assertIn("SSH-001", page)
        m = urlopen(base + "/metrics").read().decode()
        self.assertIn('fleetguard_compliance_score{host="sandbox"}', m)
        self.assertIn('fleetguard_check_failing{host="sandbox",id="SSH-001",severity="high"} 1', m)
        self.assertEqual(json.loads(urlopen(base + "/api/status").read().decode())[0]["host"], "sandbox")
        with self.assertRaises(HTTPError) as cm:
            urlopen(base + "/nope")
        self.assertEqual(cm.exception.code, 404)

    def test_empty_state_renders(self):
        self.assertIn("No scans yet", urlopen(self.start() + "/").read().decode())

    def test_token_required_when_set(self):
        base = self.start(token="s3cret")
        with self.assertRaises(HTTPError) as cm:
            urlopen(base + "/metrics")
        self.assertEqual(cm.exception.code, 401)
        ok = urlopen(Request(base + "/metrics", headers={"Authorization": "Bearer s3cret"}))
        self.assertEqual(ok.status, 200)

    def test_refuses_public_bind_without_token(self):
        with self.assertRaises(SystemExit):
            web.serve(self.store, host="0.0.0.0", port=0)

    def test_html_injection_in_hostname_escaped(self):
        self.store.write_json("scans/x/latest.json", {"host": "<img src=x>", "ts": 1, "time": "t", "reachable": True,
                                                       "score": 50.0, "summary": {"PASS": 1, "FAIL": 1, "SKIP": 0, "ERROR": 0},
                                                       "results": []})
        page = urlopen(self.start() + "/").read().decode()
        self.assertNotIn("<img src=x>", page)


class CliTests(SandboxCase):
    def test_scan_exit_codes_and_fix_flow(self):
        inv = tempfile.mktemp()
        open(inv, "w").write("[sandbox]\nlocal=true\nroot=%s\n" % self.root)
        self.write("etc/ssh/sshd_config", "PermitRootLogin yes\n", 0o600)
        base = ["--state", self.state]
        self.assertEqual(cli.main(base + ["scan", "-i", inv, "--check", "SSH-001", "--fail-on", "high"]), 2)
        self.assertEqual(cli.main(base + ["fix", "-i", inv, "--check", "SSH-001"]), 0)  # dry run
        self.assertIn("yes", self.read("etc/ssh/sshd_config"))
        self.assertEqual(cli.main(base + ["fix", "-i", inv, "--check", "SSH-001", "--apply"]), 0)
        self.assertEqual(cli.main(base + ["scan", "-i", inv, "--check", "SSH-001", "--fail-on", "high"]), 0)
        self.assertEqual(cli.main(base + ["rollback", "--list"]), 0)

    def test_drift_exit_code(self):
        inv = tempfile.mktemp()
        open(inv, "w").write("[sandbox]\nlocal=true\nroot=%s\n" % self.root)
        base = ["--state", self.state, "scan", "-i", inv, "--check", "SSH-001"]
        self.write("etc/ssh/sshd_config", "PermitRootLogin no\n", 0o600)
        self.assertEqual(cli.main(base + ["--save-baseline"]), 0)
        self.write("etc/ssh/sshd_config", "PermitRootLogin yes\n", 0o600)
        self.assertEqual(cli.main(base + ["--drift"]), 3)


class DocsTests(unittest.TestCase):
    def test_checks_doc_is_current(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        import importlib.util
        spec = importlib.util.spec_from_file_location("gen_checks", os.path.join(here, "docs", "gen_checks.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with open(os.path.join(here, "docs", "CHECKS.md")) as fh:
            self.assertEqual(fh.read(), mod.render(), "run: python3 docs/gen_checks.py")
