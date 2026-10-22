"""Safe remediation: dry-run by default, snapshot before change, verify after,
auto-rollback on failure, manual rollback from a journal."""
import shlex
import uuid

from . import checks as C
from .scan import run_check
from .store import now, iso


def _snapshot(transport, paths):
    snap = {}
    for p in paths:
        q = shlex.quote
        r = transport.run('f="$FG_ROOT"%s; if [ -e "$f" ]; then echo present; stat -c %%a "$f"; '
                          'base64 < "$f"; else echo absent; fi' % q(p))
        lines = r.out.splitlines()
        if r.rc != 0 or not lines:
            raise RuntimeError("cannot snapshot %s: %s" % (p, r.err.strip()))
        if lines[0] == "absent":
            snap[p] = {"existed": False}
        else:
            snap[p] = {"existed": True, "mode": lines[1], "b64": "".join(lines[2:])}
    return snap


def _restore(transport, snap):
    errors = []
    for p, s in snap.items():
        q = shlex.quote(p)
        if not s["existed"]:
            r = transport.run('rm -f "$FG_ROOT"%s' % q)
        else:
            r = transport.run('f="$FG_ROOT"%s; base64 -d > "$f" && chmod %s "$f"' % (q, s["mode"]),
                              stdin=s["b64"] + "\n")
        if r.rc != 0:
            errors.append("%s: %s" % (p, r.err.strip()))
    return errors


def plan(report, registry, only=None):
    items = []
    for r in report["results"]:
        if r["status"] != C.FAIL:
            continue
        if only and r["id"] not in only:
            continue
        chk = registry.get(r["id"])
        if chk is None or chk.fix is None:
            continue
        items.append({"id": chk.id, "title": chk.title, "description": chk.fix.description,
                      "risky": chk.fix.risky, "files": chk.fix.files})
    return items


def apply_fix(host, check, store, allow_risky=False, live_post=True):
    """Apply one fix. Returns a dict describing the outcome."""
    t = host.transport()
    fx = check.fix
    out = {"id": check.id, "host": host.name, "description": fx.description}
    if fx.risky and not allow_risky:
        out.update(outcome="skipped", detail="risky fix; rerun with --allow-risky")
        return out
    try:
        snap = _snapshot(t, fx.files)
    except RuntimeError as e:
        out.update(outcome="error", detail=str(e))
        return out
    jid = "%s-%s" % (iso(now()).replace(":", ""), uuid.uuid4().hex[:6])
    entry = {"id": jid, "ts": now(), "host": host.name, "check": check.id,
             "description": fx.description, "snapshot": snap, "state": "applying",
             "post": fx.post}
    store.write_json("journal/%s.json" % jid, entry)
    r = t.run(fx.script, timeout=60)
    ok = r.rc == 0
    detail = r.err.strip()
    if ok:
        res = run_check(t, check)
        ok = res["status"] == C.PASS
        if not ok:
            detail = "verification failed: %s (%s)" % (res["status"], res["observed"])
    if not ok:
        errs = _restore(t, snap)
        entry["state"] = "auto-rolled-back"
        store.write_json("journal/%s.json" % jid, entry)
        store.event("fix", host.name, "%s fix failed and was rolled back: %s" % (check.id, detail),
                    "high", check=check.id, journal=jid)
        out.update(outcome="rolled-back", detail=detail, journal=jid,
                   restore_errors=errs)
        return out
    post_note = ""
    if fx.post and live_post and not getattr(t, "root", ""):
        pr = t.run(fx.post, timeout=30)
        if pr.rc != 0:
            post_note = "post step failed: %s" % pr.err.strip()
    entry["state"] = "applied"
    store.write_json("journal/%s.json" % jid, entry)
    store.event("fix", host.name, "%s fixed: %s" % (check.id, fx.description), "medium",
                check=check.id, journal=jid)
    out.update(outcome="fixed", journal=jid, detail=post_note)
    return out


def list_journal(store):
    import os
    d = os.path.join(store.root, "journal")
    out = []
    if os.path.isdir(d):
        for n in sorted(os.listdir(d)):
            if n.endswith(".json"):
                e = store.read_json("journal/" + n)
                if e:
                    out.append(e)
    return out


def rollback(host, journal_id, store):
    entry = store.read_json("journal/%s.json" % journal_id)
    if entry is None:
        raise KeyError("no journal entry %s" % journal_id)
    if entry["host"] != host.name:
        raise ValueError("journal %s belongs to host %s, not %s" % (journal_id, entry["host"], host.name))
    if entry["state"] == "rolled-back":
        return {"journal": journal_id, "outcome": "already-rolled-back", "errors": []}
    t = host.transport()
    errs = _restore(t, entry["snapshot"])
    if not errs and entry.get("post") and not getattr(t, "root", ""):
        t.run(entry["post"], timeout=30)
    if not errs:
        entry["state"] = "rolled-back"
        entry["rolled_back_at"] = now()
        store.write_json("journal/%s.json" % journal_id, entry)
        store.event("rollback", host.name, "journal %s rolled back (%s)" % (journal_id, entry["check"]),
                    "medium", journal=journal_id)
    return {"journal": journal_id, "outcome": "rolled-back" if not errs else "error", "errors": errs}
