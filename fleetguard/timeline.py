"""Incident timeline: one chronological view of everything Guardian saw or did,
optionally merged with failed-login bursts parsed from an auth log."""
import html
import re
import time

from .store import iso

SSH_FAIL = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\s+\S+\s+sshd\[\d+\]:\s+"
                      r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)")
MONTHS = {m: i + 1 for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
                                          "Aug", "Sep", "Oct", "Nov", "Dec"])}


def parse_auth_log(path, year=None, host="localhost", burst_threshold=5, window=300):
    """Group sshd failures from one source IP inside `window` seconds into bursts."""
    year = year or time.gmtime().tm_year
    fails = {}
    with open(path, errors="replace") as fh:
        for line in fh:
            m = SSH_FAIL.match(line)
            if not m:
                continue
            mon, day, hms, user, ip = m.groups()
            if mon not in MONTHS:
                continue
            t = time.mktime((year, MONTHS[mon], int(day)) + tuple(int(x) for x in hms.split(":")) + (0, 0, -1))
            fails.setdefault(ip, []).append((t, user))
    events = []
    for ip, items in fails.items():
        items.sort()
        i = 0
        while i < len(items):
            j = i
            while j + 1 < len(items) and items[j + 1][0] - items[i][0] <= window:
                j += 1
            n = j - i + 1
            if n >= burst_threshold:
                users = sorted(set(u for _, u in items[i:j + 1]))
                events.append({"ts": items[i][0], "kind": "auth-burst", "host": host, "severity": "high",
                               "message": "%d failed SSH logins from %s in %ds (users: %s)" % (
                                   n, ip, int(items[j][0] - items[i][0]), ", ".join(users[:5]))})
            i = j + 1
    return events


def build(events, since=None, until=None, hosts=None):
    out = []
    for e in events:
        if since and e["ts"] < since:
            continue
        if until and e["ts"] > until:
            continue
        if hosts and e["host"] not in hosts:
            continue
        out.append(e)
    out.sort(key=lambda e: e["ts"])
    return out


def to_markdown(events, title="Incident timeline"):
    lines = ["# %s" % title, "", "%d event(s)." % len(events), "",
             "| Time (UTC) | Host | Kind | Severity | What happened |", "|---|---|---|---|---|"]
    for e in events:
        lines.append("| %s | %s | %s | %s | %s |" % (iso(e["ts"]), e["host"], e["kind"], e["severity"],
                                                    e["message"].replace("|", "/")))
    return "\n".join(lines) + "\n"


def to_html(events, title="Incident timeline"):
    rows = []
    for e in events:
        rows.append("<tr class='sev-%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            html.escape(e["severity"]), iso(e["ts"]), html.escape(e["host"]), html.escape(e["kind"]),
            html.escape(e["severity"]), html.escape(e["message"])))
    return ("<!doctype html><meta charset=utf-8><title>%s</title><style>body{font:14px system-ui;margin:2rem}"
            "table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 8px;text-align:left}"
            ".sev-high{background:#fde8e8}.sev-medium{background:#fff6e0}</style><h1>%s</h1>"
            "<table><tr><th>Time (UTC)</th><th>Host</th><th>Kind</th><th>Severity</th><th>What happened</th></tr>%s</table>"
            % (html.escape(title), html.escape(title), "".join(rows)))
