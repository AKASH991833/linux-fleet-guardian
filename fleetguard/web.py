"""Read-only web panel plus a Prometheus /metrics endpoint.

Binds to 127.0.0.1 by default. Binding elsewhere requires a bearer token
(--token or FLEETGUARD_TOKEN); the panel is read-only and shows no secrets, but
scan details help an attacker, so do not expose it without TLS in front.
"""
import hmac
import html
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import timeline
from .store import iso

CSS = ("body{font:14px/1.5 system-ui,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}"
       "header{padding:1rem 2rem;background:#111c33;border-bottom:1px solid #1e293b}"
       "h1{margin:0;font-size:1.2rem}main{padding:1.5rem 2rem}"
       ".cards{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}"
       ".card{background:#111c33;border:1px solid #1e293b;border-radius:10px;padding:1rem 1.2rem;min-width:200px}"
       ".big{font-size:2rem;font-weight:700}.good{color:#4ade80}.warn{color:#fbbf24}.bad{color:#f87171}"
       "table{border-collapse:collapse;width:100%;margin-bottom:2rem}"
       "td,th{padding:6px 10px;border-bottom:1px solid #1e293b;text-align:left}"
       "th{color:#94a3b8;font-weight:600}a{color:#7dd3fc}")


def load_state(store):
    hosts = []
    scans = os.path.join(store.root, "scans")
    if os.path.isdir(scans):
        for name in sorted(os.listdir(scans)):
            rep = store.read_json("scans/%s/latest.json" % name)
            if rep:
                hosts.append(rep)
    return hosts


def metrics_text(store):
    hosts = load_state(store)
    L = []

    def meta(name, help_, typ="gauge"):
        L.append("# HELP %s %s" % (name, help_))
        L.append("# TYPE %s %s" % (name, typ))

    def lbl(**kw):
        return "{" + ",".join('%s="%s"' % (k, str(v).replace("\\", "\\\\").replace('"', '\\"')) for k, v in kw.items()) + "}"

    meta("fleetguard_host_reachable", "1 if the last scan could reach the host")
    for h in hosts:
        L.append("fleetguard_host_reachable%s %d" % (lbl(host=h["host"]), 1 if h["reachable"] else 0))
    meta("fleetguard_compliance_score", "Percent of applicable checks passing (0-100)")
    for h in hosts:
        if h["score"] is not None:
            L.append("fleetguard_compliance_score%s %s" % (lbl(host=h["host"]), h["score"]))
    meta("fleetguard_checks", "Number of checks by status")
    for h in hosts:
        for st, n in sorted(h["summary"].items()):
            L.append("fleetguard_checks%s %d" % (lbl(host=h["host"], status=st), n))
    meta("fleetguard_check_failing", "1 for every failing check")
    for h in hosts:
        for r in h["results"]:
            if r["status"] == "FAIL":
                L.append("fleetguard_check_failing%s 1" % lbl(host=h["host"], id=r["id"], severity=r["severity"]))
    meta("fleetguard_last_scan_timestamp_seconds", "Unix time of the last scan")
    for h in hosts:
        L.append("fleetguard_last_scan_timestamp_seconds%s %d" % (lbl(host=h["host"]), int(h["ts"])))
    meta("fleetguard_events_total", "Events recorded, by kind", "counter")
    counts = {}
    for e in store.read_jsonl("events.jsonl"):
        counts[e["kind"]] = counts.get(e["kind"], 0) + 1
    for k, n in sorted(counts.items()):
        L.append("fleetguard_events_total%s %d" % (lbl(kind=k), n))
    meta("fleetguard_perf", "Latest performance sample per host")
    pdir = os.path.join(store.root, "perf")
    if os.path.isdir(pdir):
        for fn in sorted(os.listdir(pdir)):
            if fn.endswith(".jsonl"):
                rows = store.read_jsonl("perf/" + fn)
                if rows:
                    for m, v in sorted(rows[-1].items()):
                        if m != "ts":
                            L.append("fleetguard_perf%s %s" % (lbl(host=fn[:-6], metric=m), v))
    return "\n".join(L) + "\n"


def dashboard_html(store):
    hosts = load_state(store)
    events = timeline.build(store.read_jsonl("events.jsonl"))[-30:][::-1]
    total_fail = sum(h["summary"]["FAIL"] for h in hosts)
    scores = [h["score"] for h in hosts if h["score"] is not None]
    avg = round(sum(scores) / len(scores), 1) if scores else None
    cls = "good" if avg and avg >= 90 else "warn" if avg and avg >= 70 else "bad"
    rows = []
    for h in hosts:
        sc = h["score"]
        c = "good" if sc and sc >= 90 else "warn" if sc and sc >= 70 else "bad"
        rows.append("<tr><td>%s</td><td class=%s>%s</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td></tr>" % (
            html.escape(h["host"]), c, "unreachable" if not h["reachable"] else "%s%%" % sc,
            h["summary"]["FAIL"], h["summary"]["PASS"], "yes" if h["reachable"] else "NO", html.escape(h["time"])))
    fails = []
    for h in hosts:
        for r in h["results"]:
            if r["status"] == "FAIL":
                fails.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                    html.escape(h["host"]), html.escape(r["id"]), html.escape(r["severity"]),
                    html.escape(r["title"]), html.escape(str(r["observed"]))))
    ev = ["<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
        iso(e["ts"]), html.escape(e["host"]), html.escape(e["kind"]), html.escape(e["message"])) for e in events]
    return ("<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            "<meta http-equiv=refresh content=60><title>Linux Fleet Guardian</title><style>%s</style></head><body>"
            "<header><h1>Linux Fleet Guardian</h1></header><main>"
            "<div class=cards><div class=card><div>Hosts</div><div class=big>%d</div></div>"
            "<div class=card><div>Average compliance</div><div class='big %s'>%s</div></div>"
            "<div class=card><div>Failing checks</div><div class='big %s'>%d</div></div></div>"
            "<h2>Hosts</h2><table><tr><th>Host</th><th>Score</th><th>Fail</th><th>Pass</th><th>Reachable</th><th>Last scan</th></tr>%s</table>"
            "<h2>Failing checks</h2><table><tr><th>Host</th><th>ID</th><th>Severity</th><th>Rule</th><th>Observed</th></tr>%s</table>"
            "<h2>Recent events</h2><table><tr><th>Time (UTC)</th><th>Host</th><th>Kind</th><th>Message</th></tr>%s</table>"
            "<p><a href=/metrics>/metrics</a> &middot; <a href=/api/status>/api/status</a></p></main></body></html>" % (
                CSS, len(hosts), cls, "n/a" if avg is None else "%s%%" % avg,
                "bad" if total_fail else "good", total_fail,
                "".join(rows) or "<tr><td colspan=6>No scans yet. Run: fleetguard scan</td></tr>",
                "".join(fails) or "<tr><td colspan=5>None</td></tr>",
                "".join(ev) or "<tr><td colspan=4>No events yet</td></tr>"))


def make_handler(store, token=None):
    class H(BaseHTTPRequestHandler):
        server_version = "FleetGuardian"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self):
            if not token:
                return True
            got = self.headers.get("Authorization", "")
            return hmac.compare_digest(got, "Bearer " + token)

        def do_GET(self):
            if not self._authorized():
                self._send(401, "unauthorized\n", "text/plain")
                return
            path = self.path.split("?")[0]
            if path == "/":
                self._send(200, dashboard_html(store), "text/html; charset=utf-8")
            elif path == "/metrics":
                self._send(200, metrics_text(store), "text/plain; version=0.0.4")
            elif path == "/api/status":
                self._send(200, json.dumps(load_state(store), indent=2), "application/json")
            elif path == "/timeline":
                ev = timeline.build(store.read_jsonl("events.jsonl"))
                self._send(200, timeline.to_html(ev), "text/html; charset=utf-8")
            elif path == "/healthz":
                self._send(200, "ok\n", "text/plain")
            else:
                self._send(404, "not found\n", "text/plain")
    return H


def serve(store, host="127.0.0.1", port=9877, token=None, refresher=None, interval=0):
    if host not in ("127.0.0.1", "::1", "localhost") and not token:
        raise SystemExit("refusing to bind %s without --token (or FLEETGUARD_TOKEN)" % host)
    srv = HTTPServer((host, port), make_handler(store, token))
    if refresher and interval > 0:
        def loop():
            while True:
                try:
                    refresher()
                except Exception as e:  # keep serving even if one scan round fails
                    store.event("scan", "-", "periodic refresh failed: %s" % e, "high")
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True).start()
    return srv
