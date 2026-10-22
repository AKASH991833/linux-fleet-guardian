# Architecture

```
inventory.ini --> Host --> Transport (local sh | ssh)
                              |
   Registry of Checks ---> probe (shell) --> evaluate (Python) --> PASS/FAIL/SKIP/ERROR
        ^  plugins/                                |
        |                                          v
  Fix (files, script, post)                 scan.py: reports, scores, baseline, drift
        |                                          |
 remediate.py: snapshot -> script -> verify        v
        -> auto-rollback / journal            store.py: scans, journal, events.jsonl, perf/*.jsonl
                                                   |
        backup.py (backup, restore-test, drill)    +--> timeline.py (Markdown/HTML)
        perf.py   (sample, robust-z anomalies)     +--> web.py (panel, /metrics, /api/status)
```

## Modules

| Module | Job |
|---|---|
| `transport.py` | `LocalTransport`, `SSHTransport`, `FakeTransport`. One method: `run(cmd, timeout, stdin)`. |
| `inventory.py` | Reads the INI file into `Host` objects. |
| `checks.py` | `Check`, `Fix`, `Registry`, evaluators, and the built-in rules. |
| `plugins.py` | Loads JSON and Python plugins from a directory. |
| `scan.py` | Runs checks, scores hosts, writes reports and events, diffs against a baseline. |
| `remediate.py` | Plan, apply (snapshot, run, verify, rollback on failure), journal, manual rollback. |
| `backup.py` | Backup with manifest, restore-test, DR drill. |
| `perf.py` | Parses `/proc` probes, keeps history, flags anomalies. |
| `timeline.py` | Merges events and auth-log bursts, renders Markdown or HTML. |
| `web.py` | `http.server` panel, `/metrics`, `/api/status`, `/timeline`, `/healthz`. |
| `cli.py` | `argparse` front end. |

## Design decisions

- **Shell probes, Python judgement.** A probe prints a value; the evaluator decides. That keeps remote execution trivial (`ssh host sh -c ...`) and the logic unit-testable with canned output.
- **State is plain files.** JSON for latest state, JSONL for history. Easy to inspect, back up and diff. No database.
- **Fixes carry their own safety net.** The fix runs, the same check runs again, and only a PASS keeps the change. Anything else restores the snapshot. A drop-in file that silently overrides your edit therefore cannot leave a half-applied change behind.
- **`FG_ROOT`.** Probes and fixes build paths as `$FG_ROOT/etc/...`. Empty in production; tests point it at a temp tree so real fixes and rollbacks run for real without touching the machine.
- **Robust statistics for anomalies.** Median and MAD ignore past spikes; a minimum absolute change stops quiet hosts from alerting on noise.
- **Read-only network surface.** The only listening component is the panel, loopback by default, token required otherwise.
