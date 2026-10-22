"""Run checks against hosts and compare results to a saved baseline (drift)."""
from concurrent.futures import ThreadPoolExecutor

from . import checks as C
from .store import now, iso


def run_check(transport, check):
    r = transport.run(check.probe, timeout=30)
    if r.rc == 124 or r.rc == 127 or (r.rc == 255 and not r.out):
        return {"id": check.id, "status": C.ERROR, "observed": (r.err.strip() or "transport failure")[:200],
                "title": check.title, "severity": check.severity, "cis": check.cis}
    try:
        status, observed = check.evaluate(r.out)
    except Exception as e:  # a buggy plugin must not kill the scan
        status, observed = C.ERROR, "evaluator crashed: %s" % e
    return {"id": check.id, "status": status, "observed": observed, "title": check.title,
            "severity": check.severity, "cis": check.cis, "fixable": check.fix is not None}


def scan_host(host, checks):
    t = host.transport()
    started = now()
    results = [run_check(t, c) for c in checks]
    if results and all(r["status"] == C.ERROR for r in results):
        reachable = False
    else:
        reachable = True
    summary = {s: 0 for s in (C.PASS, C.FAIL, C.SKIP, C.ERROR)}
    for r in results:
        summary[r["status"]] += 1
    scored = summary[C.PASS] + summary[C.FAIL]
    score = round(100.0 * summary[C.PASS] / scored, 1) if scored else None
    return {"host": host.name, "ts": started, "time": iso(started), "reachable": reachable,
            "summary": summary, "score": score, "results": results}


def scan_fleet(hosts, checks, store, workers=8):
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(hosts)))) as ex:
        reports = list(ex.map(lambda h: scan_host(h, checks), hosts))
    for rep in reports:
        name = rep["host"]
        prev = store.read_json("scans/%s/latest.json" % name)
        store.write_json("scans/%s/latest.json" % name, rep)
        store.append_jsonl("scans/%s/history.jsonl" % name,
                           {"ts": rep["ts"], "summary": rep["summary"], "score": rep["score"]})
        if not rep["reachable"]:
            store.event("scan", name, "host unreachable or all checks errored", "high")
            continue
        fails = rep["summary"][C.FAIL]
        store.event("scan", name, "scan finished: %d fail, %d pass, score %s" % (
            fails, rep["summary"][C.PASS], rep["score"]), "medium" if fails else "info")
        if prev:
            for d in diff_reports(prev, rep):
                store.event("drift", name, d["message"], "high" if d["kind"] == "regressed" else "info",
                            check=d["id"])
    return reports


def _by_id(rep):
    return {r["id"]: r for r in rep["results"]}


def diff_reports(old, new):
    """Compare two reports of one host. Returns regressed/improved/new/removed items."""
    a, b = _by_id(old), _by_id(new)
    out = []
    for cid in sorted(set(a) | set(b)):
        if cid not in b:
            out.append({"id": cid, "kind": "removed", "message": "%s no longer evaluated" % cid})
            continue
        if cid not in a:
            out.append({"id": cid, "kind": "new", "message": "%s newly evaluated: %s" % (cid, b[cid]["status"])})
            continue
        sa, sb = a[cid]["status"], b[cid]["status"]
        if sa == sb:
            continue
        if sa == C.PASS and sb == C.FAIL:
            kind = "regressed"
        elif sa == C.FAIL and sb == C.PASS:
            kind = "improved"
        else:
            kind = "changed"
        out.append({"id": cid, "kind": kind,
                    "message": "%s %s: %s -> %s (%s)" % (cid, kind, sa, sb, b[cid]["observed"])})
    return out


def save_baseline(store, report):
    return store.write_json("baselines/%s.json" % report["host"], report)


def drift_against_baseline(store, report):
    base = store.read_json("baselines/%s.json" % report["host"])
    if base is None:
        return None
    return diff_reports(base, report)
