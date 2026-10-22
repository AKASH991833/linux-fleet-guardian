import argparse
import json
import os
import sys
import time

from . import __version__, backup as B, checks as C, inventory, perf, plugins, remediate, report, scan, timeline, web
from .store import Store

SEV_RANK = {"low": 1, "medium": 2, "high": 3}


def _load_registry(args):
    reg = C.builtin_registry()
    for d in (args.plugins or []):
        plugins.load_dir(reg, d)
    return reg


def _hosts(args):
    if args.inventory:
        hs = inventory.load(args.inventory)
    else:
        hs = [inventory.local_host()]
    if args.limit:
        wanted = set(args.limit.split(","))
        hs = [h for h in hs if h.name in wanted]
        if not hs:
            raise SystemExit("no host matches --limit %s" % args.limit)
    return hs


def _emit(text, out):
    if out:
        with open(out, "w") as fh:
            fh.write(text)
        print("wrote %s" % out)
    else:
        sys.stdout.write(text)


def cmd_checks(args):
    for c in _load_registry(args).all():
        print("%-8s %-6s %-30s %s%s" % (c.id, c.severity, c.cis, c.title, "  [fix]" if c.fix else ""))
    return 0


def cmd_scan(args):
    store = Store(args.state)
    reg = _load_registry(args)
    ids = args.check.split(",") if args.check else None
    chk = reg.select(ids=ids, tags=args.tag.split(",") if args.tag else None)
    if not chk:
        raise SystemExit("no checks selected")
    reports = scan.scan_fleet(_hosts(args), chk, store)
    fmt = args.format
    text = {"text": report.to_text, "json": report.to_json, "markdown": report.to_markdown,
            "junit": report.to_junit}[fmt](reports)
    _emit(text, args.output)
    if args.save_baseline:
        for r in reports:
            scan.save_baseline(store, r)
        print("baseline saved for %d host(s)" % len(reports), file=sys.stderr)
    drifted = False
    if args.drift:
        for r in reports:
            d = scan.drift_against_baseline(store, r)
            if d is None:
                print("%s: no baseline yet (use --save-baseline)" % r["host"], file=sys.stderr)
                continue
            for item in d:
                print("DRIFT %s: %s" % (r["host"], item["message"]))
                if item["kind"] == "regressed":
                    drifted = True
    worst = 0
    for r in reports:
        if not r["reachable"]:
            worst = 3
        for x in r["results"]:
            if x["status"] == C.FAIL:
                worst = max(worst, SEV_RANK[x["severity"]])
    if drifted:
        return 3
    if args.fail_on and worst >= SEV_RANK[args.fail_on]:
        return 2
    return 0


def cmd_fix(args):
    store = Store(args.state)
    reg = _load_registry(args)
    only = args.check.split(",") if args.check else None
    rc = 0
    for host in _hosts(args):
        chk = reg.select(ids=only)
        rep = scan.scan_host(host, chk)
        items = remediate.plan(rep, reg, only)
        if not items:
            print("%s: nothing to fix" % host.name)
            continue
        for it in items:
            print("%s %s%s: %s" % ("PLAN" if not args.apply else "FIX ", it["id"],
                                   " (risky)" if it["risky"] else "", it["description"]))
        if not args.apply:
            print("%s: dry run only. Re-run with --apply to change anything." % host.name)
            continue
        for it in items:
            res = remediate.apply_fix(host, reg.get(it["id"]), store, allow_risky=args.allow_risky)
            print("  -> %s %s %s%s" % (res["id"], res["outcome"], res.get("journal", ""),
                                       (" - " + res["detail"]) if res.get("detail") else ""))
            if res["outcome"] in ("rolled-back", "error"):
                rc = 1
    return rc


def cmd_rollback(args):
    store = Store(args.state)
    if args.list or not args.journal:
        for e in remediate.list_journal(store):
            print("%s  %-16s %-8s %-16s %s" % (e["id"], e["host"], e["check"], e["state"], e["description"]))
        return 0
    host = [h for h in _hosts(args) if h.name == args.host][0] if args.host else _hosts(args)[0]
    res = remediate.rollback(host, args.journal, store)
    print(json.dumps(res))
    return 0 if res["outcome"] != "error" else 1


def cmd_perf(args):
    store = Store(args.state)
    rc = 0
    for host in _hosts(args):
        if args.action == "sample":
            s = perf.sample(host, store)
            print("%s %s" % (host.name, json.dumps(s, sort_keys=True)))
        else:
            r = perf.check(host, store)
            state = "learning (%d/%d samples)" % (r["history"], perf.MIN_SAMPLES) if r["learning"] else "ok"
            if r["anomalies"]:
                state = "ANOMALY"
                rc = 2
            print("%s %s %s" % (host.name, state, json.dumps(r["sample"], sort_keys=True)))
            for a in r["anomalies"]:
                print("  anomaly: %s" % json.dumps(a, sort_keys=True))
    return rc


def cmd_backup(args):
    if args.action == "run":
        r = B.create_backup(args.source, args.dest, name=args.name, dump_cmd=args.dump_cmd)
        print(json.dumps(r, indent=2))
        return 0
    mp = args.manifest or B.latest_manifest(args.dest)
    r = B.restore_test(mp, rpo_seconds=args.rpo, rto_seconds=args.rto, verify_cmd=args.verify_cmd)
    store = Store(args.state)
    store.event("restore-test", os.uname().nodename, "restore-test %s: %s" % (
        os.path.basename(mp), "OK" if r["ok"] else "; ".join(r["problems"])), "info" if r["ok"] else "high")
    print(json.dumps(r, indent=2))
    return 0 if r["ok"] else 1


def cmd_drill(args):
    import tempfile
    work = args.workdir or tempfile.mkdtemp(prefix="fg-drill-")
    res = B.drill(args.source, work, rpo_seconds=args.rpo, rto_seconds=args.rto, dump_cmd=args.dump_cmd,
                  verify_cmd=args.verify_cmd)
    md = B.drill_markdown(res)
    _emit(md, args.report)
    Store(args.state).event("drill", os.uname().nodename, "DR drill %s (RTO %ss)" % (
        "passed" if res["ok"] else "FAILED: " + str(res.get("failure")), res.get("measured_rto_seconds")),
        "info" if res["ok"] else "high")
    return 0 if res["ok"] else 1


def cmd_timeline(args):
    store = Store(args.state)
    ev = store.read_jsonl("events.jsonl")
    if args.auth_log:
        ev += timeline.parse_auth_log(args.auth_log, year=args.year)
    since = time.time() - args.hours * 3600 if args.hours else None
    ev = timeline.build(ev, since=since, hosts=args.host.split(",") if args.host else None)
    text = timeline.to_html(ev) if args.format == "html" else timeline.to_markdown(ev)
    _emit(text, args.output)
    return 0


def _make_refresher(args, store):
    reg = _load_registry(args)
    hosts = _hosts(args)

    def refresh():
        scan.scan_fleet(hosts, reg.all(), store)
        for h in hosts:
            try:
                perf.check(h, store)
            except Exception as e:
                store.event("perf", h.name, "perf sample failed: %s" % e, "medium")
    return refresh


def cmd_serve(args):
    store = Store(args.state)
    refresher = None
    if args.scan_interval:
        refresher = _make_refresher(args, store)
    srv = web.serve(store, args.bind, args.port, token=args.token or os.environ.get("FLEETGUARD_TOKEN"),
                    refresher=refresher, interval=args.scan_interval)
    print("serving on http://%s:%d (state: %s)" % (args.bind, args.port, store.root))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def build_parser():
    p = argparse.ArgumentParser(prog="fleetguard", description="Audit, fix, back up and watch Linux fleets.")
    p.add_argument("--version", action="version", version="fleetguard " + __version__)
    p.add_argument("--state", help="state directory (default: $FLEETGUARD_STATE or ~/.local/state/fleetguard)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-i", "--inventory", help="INI inventory file (default: this machine only)")
    common.add_argument("--limit", help="comma-separated host names")
    common.add_argument("--plugins", action="append", help="directory with plugin checks (repeatable)")
    sub = p.add_subparsers(dest="cmd")
    sub.required = True

    s = sub.add_parser("checks", parents=[common], help="list available checks")
    s.set_defaults(fn=cmd_checks)

    s = sub.add_parser("scan", parents=[common], help="run checks on every host")
    s.add_argument("--check", help="comma-separated check IDs")
    s.add_argument("--tag", help="comma-separated tags (ssh, kernel, network, filesystem, accounts, services, logging)")
    s.add_argument("--format", choices=["text", "json", "markdown", "junit"], default="text")
    s.add_argument("-o", "--output")
    s.add_argument("--save-baseline", action="store_true", help="store this scan as the drift baseline")
    s.add_argument("--drift", action="store_true", help="report changes against the saved baseline (exit 3 on regression)")
    s.add_argument("--fail-on", choices=["low", "medium", "high"], help="exit 2 if a failure at or above this severity exists")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("fix", parents=[common], help="plan or apply reversible fixes (dry run by default)")
    s.add_argument("--check", help="only these check IDs")
    s.add_argument("--apply", action="store_true")
    s.add_argument("--allow-risky", action="store_true", help="also apply fixes that can lock you out")
    s.set_defaults(fn=cmd_fix)

    s = sub.add_parser("rollback", parents=[common], help="list journal entries or undo one")
    s.add_argument("journal", nargs="?")
    s.add_argument("--list", action="store_true")
    s.add_argument("--host")
    s.set_defaults(fn=cmd_rollback)

    s = sub.add_parser("perf", parents=[common], help="performance sample / anomaly check")
    s.add_argument("action", choices=["sample", "check"])
    s.set_defaults(fn=cmd_perf)

    s = sub.add_parser("backup", help="create a backup or restore-test one")
    s.add_argument("action", choices=["run", "restore-test"])
    s.add_argument("--source")
    s.add_argument("--dest", required=True)
    s.add_argument("--name", default="backup")
    s.add_argument("--manifest")
    s.add_argument("--dump-cmd", help="command whose stdout is saved inside the backup (e.g. mysqldump)")
    s.add_argument("--verify-cmd", help="run in the restored dir; $RESTORE_DIR is set; non-zero fails the test")
    s.add_argument("--rpo", type=int, help="max acceptable backup age in seconds")
    s.add_argument("--rto", type=int, help="max acceptable restore time in seconds")
    s.set_defaults(fn=cmd_backup)

    s = sub.add_parser("drill", help="disaster-recovery drill on a scratch copy")
    s.add_argument("--source", required=True)
    s.add_argument("--workdir")
    s.add_argument("--rpo", type=int, default=86400)
    s.add_argument("--rto", type=int, default=300)
    s.add_argument("--dump-cmd")
    s.add_argument("--verify-cmd")
    s.add_argument("--report", help="write the Markdown report here")
    s.set_defaults(fn=cmd_drill)

    s = sub.add_parser("timeline", help="incident timeline from recorded events")
    s.add_argument("--hours", type=float, help="only the last N hours")
    s.add_argument("--host")
    s.add_argument("--auth-log", help="also parse failed SSH logins from this auth log")
    s.add_argument("--year", type=int)
    s.add_argument("--format", choices=["markdown", "html"], default="markdown")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_timeline)

    s = sub.add_parser("serve", parents=[common], help="web panel + Prometheus /metrics")
    s.add_argument("--bind", default="127.0.0.1")
    s.add_argument("--port", type=int, default=9877)
    s.add_argument("--token", help="bearer token (required when not binding to loopback)")
    s.add_argument("--scan-interval", type=int, default=0, help="seconds between background scans (0 = serve stored data only)")
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (ValueError, KeyError, RuntimeError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
