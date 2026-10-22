"""Backups you can trust: create, restore-test, and run disaster-recovery drills.

A backup only counts once it has been restored and compared with what was
backed up. `restore_test` extracts into a scratch directory, checks every file
hash against the manifest, optionally runs your own verification command, and
reports measured restore time (RTO) and backup age (RPO).
"""
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time

from .store import iso


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk(src):
    out = {}
    for base, dirs, files in os.walk(src):
        dirs.sort()
        for f in sorted(files):
            full = os.path.join(base, f)
            rel = os.path.relpath(full, src)
            if os.path.islink(full):
                out[rel] = {"link": os.readlink(full)}
            elif os.path.isfile(full):
                out[rel] = {"sha256": sha256_file(full), "size": os.path.getsize(full),
                            "mode": "%o" % (os.stat(full).st_mode & 0o7777)}
    return out


def create_backup(source, dest, name="backup", dump_cmd=None):
    """tar.gz of `source` (+ optional dump command output) with a manifest."""
    source = os.path.abspath(source)
    if not os.path.isdir(source):
        raise ValueError("source %s is not a directory" % source)
    os.makedirs(dest, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    base = "%s-%s" % (name, stamp)
    archive = os.path.join(dest, base + ".tar.gz")
    stage = tempfile.mkdtemp(prefix="fg-stage-")
    try:
        staged = os.path.join(stage, "data")
        shutil.copytree(source, staged, symlinks=True)
        if dump_cmd:
            r = subprocess.run(dump_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if r.returncode != 0:
                raise RuntimeError("dump command failed (rc=%d): %s" % (
                    r.returncode, r.stderr.decode("utf-8", "replace")[:300]))
            if not r.stdout:
                raise RuntimeError("dump command produced no output")
            with open(os.path.join(staged, "_dump.out"), "wb") as fh:
                fh.write(r.stdout)
        files = _walk(staged)
        with tarfile.open(archive, "w:gz") as tf:
            tf.add(staged, arcname=".")
        manifest = {"version": 1, "created": time.time(), "created_iso": iso(time.time()),
                    "source": source, "archive": os.path.basename(archive),
                    "archive_sha256": sha256_file(archive), "file_count": len(files),
                    "has_dump": bool(dump_cmd), "files": files}
        mpath = os.path.join(dest, base + ".manifest.json")
        with open(mpath, "w") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
        return {"archive": archive, "manifest": mpath, "files": len(files),
                "bytes": os.path.getsize(archive)}
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _safe_members(tf, target):
    root = os.path.realpath(target)
    for m in tf.getmembers():
        dest = os.path.realpath(os.path.join(root, m.name))
        if not (dest == root or dest.startswith(root + os.sep)):
            raise RuntimeError("unsafe path in archive: %s" % m.name)
        if m.islnk():
            raise RuntimeError("hard link in archive: %s" % m.name)
        if m.issym():
            link_target = os.path.realpath(os.path.join(os.path.dirname(dest), m.linkname))
            if os.path.isabs(m.linkname) or not (link_target == root or link_target.startswith(root + os.sep)):
                raise RuntimeError("unsafe symlink in archive: %s -> %s" % (m.name, m.linkname))
        if m.isdev():
            raise RuntimeError("device node in archive: %s" % m.name)
        yield m


def latest_manifest(dest):
    cands = sorted(n for n in os.listdir(dest) if n.endswith(".manifest.json"))
    if not cands:
        raise ValueError("no manifest in %s" % dest)
    return os.path.join(dest, cands[-1])


def restore_test(manifest_path, rpo_seconds=None, rto_seconds=None, verify_cmd=None,
                 keep_dir=None):
    """Restore into a scratch dir and prove the contents match the manifest."""
    with open(manifest_path) as fh:
        man = json.load(fh)
    archive = os.path.join(os.path.dirname(os.path.abspath(manifest_path)), man["archive"])
    problems = []
    rep = {"manifest": manifest_path, "archive": archive, "created": man.get("created_iso"),
           "problems": problems}
    age = time.time() - man["created"]
    rep["age_seconds"] = int(age)
    if not os.path.exists(archive):
        problems.append("archive file missing")
        rep["ok"] = False
        return rep
    if sha256_file(archive) != man["archive_sha256"]:
        problems.append("archive checksum mismatch (corrupt or tampered)")
        rep["ok"] = False
        return rep
    scratch = keep_dir or tempfile.mkdtemp(prefix="fg-restore-")
    os.makedirs(scratch, exist_ok=True)
    t0 = time.time()
    try:
        with tarfile.open(archive, "r:gz") as tf:
            members = list(_safe_members(tf, scratch))
            tf.extractall(scratch, members=members)
        rep["restore_seconds"] = round(time.time() - t0, 3)
        got = _walk(scratch)
        want = man["files"]
        missing = sorted(set(want) - set(got))
        extra = sorted(set(got) - set(want))
        bad = sorted(k for k in want if k in got and want[k] != got[k]
                     and ("sha256" in want[k] or "link" in want[k])
                     and (want[k].get("sha256") != got[k].get("sha256")
                          or want[k].get("link") != got[k].get("link")))
        if missing:
            problems.append("%d file(s) missing after restore, e.g. %s" % (len(missing), missing[:3]))
        if extra:
            problems.append("%d unexpected file(s), e.g. %s" % (len(extra), extra[:3]))
        if bad:
            problems.append("%d file(s) differ from manifest, e.g. %s" % (len(bad), bad[:3]))
        rep["files_expected"] = len(want)
        rep["files_restored"] = len(got)
        if man.get("has_dump"):
            d = os.path.join(scratch, "_dump.out")
            if not os.path.exists(d) or os.path.getsize(d) == 0:
                problems.append("database dump is missing or empty")
        if verify_cmd:
            env = dict(os.environ, RESTORE_DIR=scratch)
            r = subprocess.run(verify_cmd, shell=True, cwd=scratch, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, universal_newlines=True)
            rep["verify_cmd_rc"] = r.returncode
            if r.returncode != 0:
                problems.append("verify command failed (rc=%d): %s" % (r.returncode, r.stderr.strip()[:200]))
    except Exception as e:
        problems.append("restore failed: %s" % e)
    finally:
        if not keep_dir:
            shutil.rmtree(scratch, ignore_errors=True)
    if rpo_seconds is not None and age > rpo_seconds:
        problems.append("RPO missed: newest backup is %ds old, target %ds" % (age, rpo_seconds))
    if rto_seconds is not None and rep.get("restore_seconds", 0) > rto_seconds:
        problems.append("RTO missed: restore took %.1fs, target %ss" % (rep["restore_seconds"], rto_seconds))
    rep["ok"] = not problems
    return rep


def drill(source, workdir, rpo_seconds=86400, rto_seconds=300, dump_cmd=None, verify_cmd=None):
    """Disaster-recovery drill on a scratch copy; the real source is read-only here.

    1 back up the source  2 copy it to a scratch 'production'  3 destroy the copy
    4 restore the backup into its place  5 compare with the source  6 time it all.
    """
    os.makedirs(workdir, exist_ok=True)
    steps = []
    t_all = time.time()

    def step(name, fn):
        t = time.time()
        try:
            detail = fn()
            steps.append({"step": name, "ok": True, "seconds": round(time.time() - t, 3), "detail": detail})
            return detail
        except Exception as e:
            steps.append({"step": name, "ok": False, "seconds": round(time.time() - t, 3), "detail": str(e)})
            raise

    bdir = os.path.join(workdir, "backups")
    prod = os.path.join(workdir, "scratch-production")
    result = {"started": iso(t_all), "source": os.path.abspath(source), "targets": {
        "rpo_seconds": rpo_seconds, "rto_seconds": rto_seconds}, "steps": steps}
    try:
        b = step("backup", lambda: create_backup(source, bdir, "drill", dump_cmd=dump_cmd))
        step("clone to scratch production", lambda: shutil.copytree(source, prod, symlinks=True) and "ok")
        step("simulate disaster (delete scratch production)", lambda: shutil.rmtree(prod) or "deleted")
        t_restore = time.time()

        def restore():
            with tarfile.open(b["archive"], "r:gz") as tf:
                os.makedirs(prod)
                tf.extractall(prod, members=list(_safe_members(tf, prod)))
            if dump_cmd:
                os.remove(os.path.join(prod, "_dump.out"))
            return "restored %d files" % b["files"]
        step("restore from backup", restore)
        rto = time.time() - t_restore

        def compare():
            want, got = _walk(source), _walk(prod)
            if want != got:
                diff = sorted(set(want) ^ set(got)) or sorted(k for k in want if want[k] != got.get(k))
                raise RuntimeError("restored data differs from source: %s" % diff[:5])
            return "%d files identical" % len(got)
        step("compare restored data with source", compare)
        rt = step("independent restore-test of the same backup",
                  lambda: restore_test(b["manifest"], rpo_seconds=rpo_seconds, rto_seconds=rto_seconds,
                                       verify_cmd=verify_cmd))
        if not rt["ok"]:
            raise RuntimeError("; ".join(rt["problems"]))
        result["measured_rto_seconds"] = round(rto, 3)
        result["rto_met"] = rto <= rto_seconds
        result["ok"] = result["rto_met"]
    except Exception as e:
        result["ok"] = False
        result["failure"] = str(e)
    result["total_seconds"] = round(time.time() - t_all, 3)
    return result


def drill_markdown(res):
    lines = ["# DR drill report", "", "- Started: %s" % res["started"], "- Source: `%s`" % res["source"],
             "- Targets: RPO %ss, RTO %ss" % (res["targets"]["rpo_seconds"], res["targets"]["rto_seconds"]),
             "- Result: **%s**" % ("PASS" if res.get("ok") else "FAIL"), ""]
    if "measured_rto_seconds" in res:
        lines.append("- Measured RTO: %ss (%s)" % (res["measured_rto_seconds"],
                                                    "met" if res["rto_met"] else "MISSED"))
    if res.get("failure"):
        lines.append("- Failure: %s" % res["failure"])
    lines += ["", "| Step | Result | Seconds | Detail |", "|---|---|---|---|"]
    for s in res["steps"]:
        d = s["detail"] if isinstance(s["detail"], str) else json.dumps(s["detail"])[:120]
        lines.append("| %s | %s | %s | %s |" % (s["step"], "ok" if s["ok"] else "FAILED", s["seconds"],
                                                 d.replace("|", "/")))
    lines += ["", "The drill only touched a scratch copy; the source was read, never modified.", ""]
    return "\n".join(lines)
