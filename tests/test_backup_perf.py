import json
import os
import shutil
import tarfile
import tempfile
import unittest

from fleetguard import backup as B, perf


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fg-bk-")
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(os.path.join(self.src, "sub"))
        with open(os.path.join(self.src, "a.txt"), "w") as f:
            f.write("alpha\n")
        with open(os.path.join(self.src, "sub", "b.bin"), "wb") as f:
            f.write(os.urandom(4096))
        os.symlink("a.txt", os.path.join(self.src, "link"))
        self.dest = os.path.join(self.tmp, "dest")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_roundtrip_ok(self):
        r = B.create_backup(self.src, self.dest, "t")
        rep = B.restore_test(r["manifest"], rpo_seconds=60, rto_seconds=30)
        self.assertTrue(rep["ok"], rep)
        self.assertEqual(rep["files_expected"], 3)

    def test_corrupt_archive_detected(self):
        r = B.create_backup(self.src, self.dest, "t")
        with open(r["archive"], "ab") as f:
            f.write(b"junk")
        rep = B.restore_test(r["manifest"])
        self.assertFalse(rep["ok"])
        self.assertIn("checksum", rep["problems"][0])

    def test_tampered_manifest_detected(self):
        r = B.create_backup(self.src, self.dest, "t")
        man = json.load(open(r["manifest"]))
        man["files"]["a.txt"]["sha256"] = "0" * 64
        json.dump(man, open(r["manifest"], "w"))
        rep = B.restore_test(r["manifest"])
        self.assertFalse(rep["ok"])
        self.assertTrue(any("differ" in p for p in rep["problems"]))

    def test_rpo_and_verify_cmd(self):
        r = B.create_backup(self.src, self.dest, "t")
        self.assertFalse(B.restore_test(r["manifest"], rpo_seconds=-1)["ok"])
        self.assertTrue(B.restore_test(r["manifest"], verify_cmd='test -f "$RESTORE_DIR/a.txt"')["ok"])
        rep = B.restore_test(r["manifest"], verify_cmd="false")
        self.assertFalse(rep["ok"])

    def test_dump_cmd_included_and_failure_reported(self):
        r = B.create_backup(self.src, self.dest, "t", dump_cmd="echo SELECT 1")
        rep = B.restore_test(r["manifest"], verify_cmd='grep -q "SELECT 1" "$RESTORE_DIR/_dump.out"')
        self.assertTrue(rep["ok"], rep)
        with self.assertRaises(RuntimeError):
            B.create_backup(self.src, self.dest, "t2", dump_cmd="exit 3")

    def test_path_traversal_archive_rejected(self):
        evil = os.path.join(self.tmp, "evil.tar.gz")
        payload = os.path.join(self.tmp, "payload")
        open(payload, "w").write("x")
        with tarfile.open(evil, "w:gz") as tf:
            tf.add(payload, arcname="../../escaped.txt")
        man = {"version": 1, "created": 0, "archive": "evil.tar.gz", "archive_sha256": B.sha256_file(evil),
               "files": {}}
        mp = os.path.join(self.tmp, "evil.manifest.json")
        json.dump(man, open(mp, "w"))
        rep = B.restore_test(mp)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("unsafe" in p for p in rep["problems"]))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "..", "escaped.txt")))

    def test_drill_passes_and_never_modifies_source(self):
        before = B._walk(self.src)
        res = B.drill(self.src, os.path.join(self.tmp, "w"), rpo_seconds=60, rto_seconds=30)
        self.assertTrue(res["ok"], res)
        self.assertEqual(B._walk(self.src), before)
        self.assertIn("PASS", B.drill_markdown(res))

    def test_drill_fails_when_rto_target_is_impossible(self):
        res = B.drill(self.src, os.path.join(self.tmp, "w2"), rto_seconds=-1)
        self.assertFalse(res["ok"])

    def test_latest_manifest_picks_newest(self):
        os.makedirs(self.dest)
        for n in ("t-20200101T000000Z.manifest.json", "t-20250101T000000Z.manifest.json"):
            open(os.path.join(self.dest, n), "w").write("{}")
        self.assertTrue(B.latest_manifest(self.dest).endswith("20250101T000000Z.manifest.json"))


class PerfTests(unittest.TestCase):
    PROBE = ("0.50 0.40 0.30 1/200 999\nMemTotal: 1000000 kB\nMemAvailable: 600000 kB\n"
             "SwapTotal: 0 kB\nSwapFree: 0 kB\n2\n 42%\n")

    def test_parse(self):
        s = perf.parse_probe(self.PROBE)
        self.assertEqual(s["load_per_cpu"], 0.25)
        self.assertEqual(s["mem_used_pct"], 40.0)
        self.assertEqual(s["swap_used_pct"], 0.0)
        self.assertEqual(s["disk_used_pct"], 42.0)

    def test_parse_garbage(self):
        with self.assertRaises(ValueError):
            perf.parse_probe("nope")

    def hist(self, n=30):
        return [{"load_per_cpu": 0.2 + (i % 3) * 0.01, "mem_used_pct": 40 + (i % 4) * 0.5,
                 "swap_used_pct": 0, "disk_used_pct": 30} for i in range(n)]

    def test_no_alerts_while_learning(self):
        self.assertEqual(perf.detect(self.hist(5), {"load_per_cpu": 9, "mem_used_pct": 99}), [])

    def test_spike_is_flagged(self):
        a = perf.detect(self.hist(), {"load_per_cpu": 3.0, "mem_used_pct": 41, "swap_used_pct": 0,
                                      "disk_used_pct": 30})
        self.assertEqual([x["metric"] for x in a], ["load_per_cpu"])

    def test_normal_noise_not_flagged(self):
        a = perf.detect(self.hist(), {"load_per_cpu": 0.22, "mem_used_pct": 41.5, "swap_used_pct": 0,
                                      "disk_used_pct": 30})
        self.assertEqual(a, [])

    def test_tiny_but_statistically_large_change_ignored(self):
        h = [{"load_per_cpu": 0.0, "mem_used_pct": 40.0, "swap_used_pct": 0, "disk_used_pct": 30} for _ in range(30)]
        self.assertEqual(perf.detect(h, {"load_per_cpu": 0.1, "mem_used_pct": 40.0, "swap_used_pct": 0,
                                         "disk_used_pct": 30}), [])
