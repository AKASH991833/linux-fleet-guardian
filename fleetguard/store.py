"""State directory: scan history, baselines, fix journal, events, perf samples."""
import json
import os
import time


def default_state_dir():
    env = os.environ.get("FLEETGUARD_STATE")
    if env:
        return env
    if os.geteuid() == 0:
        return "/var/lib/fleetguard"
    return os.path.join(os.path.expanduser("~"), ".local", "state", "fleetguard")


def now():
    return time.time()


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class Store(object):
    def __init__(self, root=None):
        self.root = root or default_state_dir()

    def path(self, *parts):
        p = os.path.join(self.root, *parts)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        return p

    def write_json(self, rel, data):
        p = self.path(*rel.split("/"))
        tmp = p + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        os.replace(tmp, p)
        return p

    def read_json(self, rel, default=None):
        p = os.path.join(self.root, *rel.split("/"))
        if not os.path.exists(p):
            return default
        with open(p) as fh:
            return json.load(fh)

    def append_jsonl(self, rel, obj):
        p = self.path(*rel.split("/"))
        with open(p, "a") as fh:
            fh.write(json.dumps(obj, sort_keys=True) + "\n")

    def read_jsonl(self, rel):
        p = os.path.join(self.root, *rel.split("/"))
        out = []
        if os.path.exists(p):
            with open(p) as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            out.append(json.loads(line))
                        except ValueError:
                            pass
        return out

    def event(self, kind, host, message, severity="info", **extra):
        ev = {"ts": now(), "kind": kind, "host": host, "severity": severity,
              "message": message}
        ev.update(extra)
        self.append_jsonl("events.jsonl", ev)
        return ev
