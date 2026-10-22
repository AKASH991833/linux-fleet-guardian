"""Performance baseline and anomaly detection with robust statistics.

Samples are stored per host. A new sample is anomalous when it is both far from
the median in robust-z terms (median/MAD) and past a minimum absolute change, so
quiet hosts do not alert on noise. Needs MIN_SAMPLES of history first.
"""
import statistics

from .store import now

MIN_SAMPLES = 12
Z_LIMIT = 4.0
PROBE = ("cat /proc/loadavg; grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo; "
         "nproc; df -P \"${FG_ROOT:-}/\" | awk 'NR==2{print $5}'")

# metric -> minimum absolute deviation worth alerting on
MIN_ABS = {"load_per_cpu": 0.5, "mem_used_pct": 10.0, "swap_used_pct": 10.0, "disk_used_pct": 5.0}


def parse_probe(text):
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < 7:
        raise ValueError("unexpected perf probe output (%d lines)" % len(lines))
    load1 = float(lines[0].split()[0])
    mem = {}
    for l in lines[1:5]:
        k, v = l.split(":")
        mem[k] = float(v.split()[0])
    cpus = int(lines[5])
    disk = float(lines[6].strip().rstrip("%"))
    mem_used = 100.0 * (1 - mem["MemAvailable"] / mem["MemTotal"]) if mem.get("MemTotal") else 0.0
    swap_used = 100.0 * (1 - mem["SwapFree"] / mem["SwapTotal"]) if mem.get("SwapTotal") else 0.0
    return {"load_per_cpu": round(load1 / max(cpus, 1), 3), "mem_used_pct": round(mem_used, 2),
            "swap_used_pct": round(swap_used, 2), "disk_used_pct": disk}


def sample(host, store):
    r = host.transport().run(PROBE)
    if r.rc != 0:
        raise RuntimeError("perf probe failed on %s: %s" % (host.name, r.err.strip()))
    s = parse_probe(r.out)
    s["ts"] = now()
    store.append_jsonl("perf/%s.jsonl" % host.name, s)
    return s


def robust_z(history, value):
    med = statistics.median(history)
    mad = statistics.median([abs(x - med) for x in history])
    scale = 1.4826 * mad
    if scale < 1e-9:
        scale = max(abs(med) * 0.05, 1e-3)
    return (value - med) / scale, med


def detect(history_samples, new_sample):
    """Return a list of anomalies for new_sample given earlier samples."""
    out = []
    if len(history_samples) < MIN_SAMPLES:
        return out
    for metric, min_abs in MIN_ABS.items():
        hist = [s[metric] for s in history_samples if metric in s]
        if len(hist) < MIN_SAMPLES or metric not in new_sample:
            continue
        z, med = robust_z(hist, new_sample[metric])
        dev = new_sample[metric] - med
        if abs(z) >= Z_LIMIT and abs(dev) >= min_abs:
            out.append({"metric": metric, "value": new_sample[metric], "baseline_median": round(med, 3),
                        "robust_z": round(z, 1)})
    return out


def check(host, store, window=288):
    """Take a sample, compare with recent history, record events for anomalies."""
    rel = "perf/%s.jsonl" % host.name
    history = store.read_jsonl(rel)[-window:]
    s = sample(host, store)
    anomalies = detect(history, s)
    for a in anomalies:
        store.event("anomaly", host.name, "%s=%s vs baseline median %s (robust z %s)" % (
            a["metric"], a["value"], a["baseline_median"], a["robust_z"]), "high", metric=a["metric"])
    return {"host": host.name, "sample": s, "history": len(history), "anomalies": anomalies,
            "learning": len(history) < MIN_SAMPLES}
