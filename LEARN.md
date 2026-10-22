# LEARN.md - understand Linux Fleet Guardian

Read this slowly, one section a day. Each part has a small exercise you can do on any Linux machine.

## 1. What problem does it solve?

You have a few servers. Over time settings drift: someone turns root login back on, a file gets the wrong permission, a backup silently stops working. Guardian checks, fixes (safely), and proves backups work.

## 2. A check is a question with a shell answer

Example: "Is SSH root login off?"

1. **Probe** (shell): print the value of `PermitRootLogin`.
2. **Evaluate** (Python): is it `no`? PASS or FAIL.

Why split it? The probe can run on any server through `ssh`. The judgement stays in one place and is easy to test.

Exercise: run `grep -i '^PermitRootLogin' /etc/ssh/sshd_config`, then `python3 -m fleetguard scan --check SSH-001`. Do they agree?

## 3. Idempotent: run it twice, same result

A fix is idempotent if running it again changes nothing. `chmod 640 /etc/shadow` is idempotent. `echo "x" >> file` is not, unless you test first (`grep -q x file || echo x >> file`). Ansible, and this tool, depend on that idea.

Exercise: run the same `fix --apply` twice. The second run says "nothing to fix".

## 4. Drift

Save a baseline when everything is good (`--save-baseline`). Later, `--drift` compares today's results with the baseline. A check going PASS to FAIL is a *regression*. Exit code 3 lets cron or CI react.

Exercise: save a baseline, edit `/etc/ssh/sshd_config` in a test VM, scan with `--drift`.

## 5. Safe change = snapshot, change, verify, undo

`remediate.py` follows four steps:

1. **Snapshot** the files the fix will touch (content and mode).
2. **Run** the fix script.
3. **Verify** by running the same check again.
4. If anything failed, **restore** the snapshot.

It also writes a **journal** entry, so you can roll back by hand tomorrow: `fleetguard rollback <id>`.

Exercise: read `apply_fix` in `fleetguard/remediate.py`. Find the four steps.

## 6. Why "dry run by default"

Tools that change servers should ask first. `fix` only prints a plan. `--apply` is explicit. Dangerous fixes also need `--allow-risky`.

## 7. A backup does not count until you restore it

Most backup failures are found during an emergency. `restore-test`:

1. checks the archive's SHA-256 (corruption or tampering),
2. extracts into a scratch folder (rejecting `../` paths, hard links, device files),
3. compares every file's hash with the manifest,
4. runs your own check (for example "does the SQL dump load?").

Exercise: run a backup, append junk to the archive with `echo x >> file.tar.gz`, run `restore-test`. It fails on the checksum.

## 8. RPO and RTO

- **RPO** (Recovery Point Objective): how much data you can lose. If backups are daily, RPO is about 24 hours.
- **RTO** (Recovery Time Objective): how long you can be down. The drill measures it.

Exercise: run `fleetguard drill --source /etc/ssh --rto 5`. Open the report. What was the measured RTO?

## 9. Robust statistics for anomalies

A fixed rule such as "load above 4" is wrong for both a tiny VM and a 64-core box. Guardian learns each host's normal:

- **median**: the typical value, not fooled by old spikes,
- **MAD** (median absolute deviation): the typical spread,
- **robust z-score** = (value - median) / (1.4826 x MAD).

It alerts when z is 4 or more *and* the change is big enough in real units. The second condition stops alerts on boring hosts where the spread is almost zero.

Exercise: in a Python shell call `fleetguard.perf.robust_z([1,1,1,2,1,1,1,1,2,1,1,1], 9)`.

## 10. Timeline thinking

During an incident you ask "what changed, and when?". Every component appends an event to `events.jsonl`. `fleetguard timeline` sorts them. With `--auth-log` it groups failed SSH logins from one IP into bursts. Good incident reports are timelines plus facts.

## 11. Reading the code in order

1. `transport.py` (50 lines): run a shell command here or over SSH.
2. `checks.py`: the rules. Find `sshd_value_probe` and `ev_equals`.
3. `scan.py`: run all checks, score, diff.
4. `remediate.py`: the safe-change loop.
5. `backup.py`: backups, restore-test, drill.
6. `perf.py`, `timeline.py`, `web.py`: observability.
7. `tests/`: how each piece is proven. Tests are documentation.

## 12. What to build next (practice)

- A check for `net.ipv4.conf.all.log_martians`.
- A JSON plugin that makes sure `/etc/issue.net` has a warning banner.
- A check that SSH `Protocol`/`Ciphers` do not allow weak algorithms (hint: `sshd -T`).
- A `fleetguard` Ansible task that runs `scan --fail-on high` after your hardening playbook.

## Glossary

| Term | Meaning |
|---|---|
| CIS Benchmark | Public, consensus hardening guides per OS |
| Drift | Config that changed away from the known-good state |
| Idempotent | Safe to run many times, same end state |
| Baseline | Saved known-good scan |
| RPO / RTO | Max data loss / max downtime |
| MAD | Median absolute deviation, a spread measure that ignores outliers |
| Journal | Record of changes made, with snapshots, so you can undo |
