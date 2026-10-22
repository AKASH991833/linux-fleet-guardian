"""Render scan reports as text, Markdown, HTML or JUnit XML."""
import json
from xml.sax.saxutils import quoteattr

ORDER = {"high": 0, "medium": 1, "low": 2}


def to_text(reports):
    out = []
    for rep in reports:
        s = rep["summary"]
        head = "%s: score %s%% (%d pass, %d fail, %d skip, %d error)" % (
            rep["host"], rep["score"], s["PASS"], s["FAIL"], s["SKIP"], s["ERROR"])
        if not rep["reachable"]:
            head = "%s: UNREACHABLE" % rep["host"]
        out.append(head)
        for r in sorted(rep["results"], key=lambda r: (r["status"] == "PASS", ORDER[r["severity"]], r["id"])):
            if r["status"] == "PASS":
                continue
            out.append("  [%s] %-8s %-6s %s -- %s" % (r["status"], r["id"], r["severity"], r["title"], r["observed"]))
    return "\n".join(out) + "\n"


def to_markdown(reports):
    out = ["# Fleet scan report", ""]
    for rep in reports:
        s = rep["summary"]
        out += ["## %s" % rep["host"], "",
                "Score **%s%%** - %d pass, %d fail, %d skipped, %d error. Scanned %s." % (
                    rep["score"], s["PASS"], s["FAIL"], s["SKIP"], s["ERROR"], rep["time"]), "",
                "| Status | ID | Severity | Rule | Observed |", "|---|---|---|---|---|"]
        for r in sorted(rep["results"], key=lambda r: (r["status"] == "PASS", ORDER[r["severity"]], r["id"])):
            out.append("| %s | %s | %s | %s | %s |" % (r["status"], r["id"], r["severity"], r["title"],
                                                      str(r["observed"]).replace("|", "/")))
        out.append("")
    return "\n".join(out)


def to_junit(reports):
    total = sum(len(r["results"]) for r in reports)
    fails = sum(r["summary"]["FAIL"] for r in reports)
    errs = sum(r["summary"]["ERROR"] for r in reports)
    parts = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<testsuites tests="%d" failures="%d" errors="%d">' % (total, fails, errs)]
    for rep in reports:
        parts.append('<testsuite name=%s tests="%d">' % (quoteattr(rep["host"]), len(rep["results"])))
        for r in rep["results"]:
            parts.append('<testcase classname=%s name=%s>' % (quoteattr(rep["host"]), quoteattr(r["id"] + " " + r["title"])))
            if r["status"] == "FAIL":
                parts.append('<failure message=%s/>' % quoteattr(str(r["observed"])))
            elif r["status"] == "ERROR":
                parts.append('<error message=%s/>' % quoteattr(str(r["observed"])))
            elif r["status"] == "SKIP":
                parts.append('<skipped message=%s/>' % quoteattr(str(r["observed"])))
            parts.append("</testcase>")
        parts.append("</testsuite>")
    parts.append("</testsuites>")
    return "\n".join(parts) + "\n"


def to_json(reports):
    return json.dumps(reports, indent=2, sort_keys=True) + "\n"
