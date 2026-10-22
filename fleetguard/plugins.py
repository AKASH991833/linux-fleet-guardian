"""Extension points.

Two kinds of plugin live in a --plugins directory:

* ``*.json``  declarative file checks (no code). A list of objects::

      {"id": "X-001", "title": "...", "severity": "medium", "file": "/etc/foo.conf",
       "regex": "^Enabled=yes", "expect": "present"}

* ``*.py``    Python modules exposing ``register(registry, checks_api)``.
  Python plugins run with your privileges: only load directories you trust.
"""
import importlib.util
import json
import os
import re

from . import checks as C


def _declarative(entry):
    for k in ("id", "title", "file", "regex"):
        if k not in entry:
            raise ValueError("plugin check missing %r: %r" % (k, entry))
    expect = entry.get("expect", "present")
    if expect not in ("present", "absent"):
        raise ValueError("expect must be present|absent in %s" % entry["id"])
    re.compile(entry["regex"])
    path = entry["file"]
    rx = entry["regex"].replace("'", "'\\''")
    probe = ('f="$FG_ROOT%s"; [ -r "$f" ] || { echo %s; exit 0; }; '
             "grep -Eq '%s' \"$f\" && echo present || echo absent" % (path, C.NA, rx))

    def ev(out, expect=expect):
        v = out.strip()
        if v == C.NA:
            return C.SKIP, "file not present"
        return (C.PASS if v == expect else C.FAIL), v
    return C.Check(entry["id"], entry["title"], entry.get("severity", "medium"),
                   entry.get("cis", "Custom"), probe, ev, tags=tuple(entry.get("tags", ["custom"])))


def load_dir(registry, path):
    loaded = []
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        if name.endswith(".json"):
            with open(full) as fh:
                data = json.load(fh)
            for entry in (data if isinstance(data, list) else [data]):
                registry.add(_declarative(entry))
            loaded.append(name)
        elif name.endswith(".py") and not name.startswith("_"):
            spec = importlib.util.spec_from_file_location("fg_plugin_" + name[:-3], full)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if not hasattr(mod, "register"):
                raise ValueError("%s has no register(registry, checks_api)" % name)
            mod.register(registry, C)
            loaded.append(name)
    return loaded
