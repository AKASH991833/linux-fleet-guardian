# Writing checks

A check is: an ID, a title, a severity, a **probe** (shell that prints a value) and an **evaluator** (Python that turns the printed value into PASS/FAIL).

## 1. No code: JSON

```json
{"id": "CUS-010", "title": "Core dumps disabled in limits.conf", "severity": "low",
 "file": "/etc/security/limits.conf", "regex": "^\\*\\s+hard\\s+core\\s+0", "expect": "present"}
```

`expect` is `present` or `absent`. If the file does not exist the check is SKIP. Put the file in any directory and pass `--plugins DIR`.

## 2. Python plugin

```python
def register(registry, api):
    def evaluate(out):
        n = int(out.strip() or 0)
        return (api.PASS if n == 0 else api.FAIL), "%d world-writable dirs" % n

    registry.add(api.Check(
        "CUS-200", "No world-writable directories without sticky bit in /var", "medium", "Custom",
        "find /var -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | wc -l", evaluate))
```

Rules for probes:

- POSIX `sh`, no bashisms. Print one value or a list of offenders (empty list means pass).
- Print `api.NA` (`__NA__`) when the check does not apply (file or tool missing). It becomes SKIP, not a false FAIL.
- Prefix file paths with `$FG_ROOT` so your check can be tested in a temp tree.
- Do not change anything in a probe.

## 3. Adding a fix

```python
fix = api.Fix("Set umask 027 in /etc/profile", ["/etc/profile"],
              'f="$FG_ROOT/etc/profile"; grep -q "^umask 027" "$f" || echo "umask 027" >> "$f"')
api.Check(..., fix=fix)
```

- List every file the script touches in `files`; those are snapshotted and restored on rollback.
- Exit non-zero on any failure.
- `post` runs after a verified fix on a live system only (for example a service reload).
- Set `risky=True` if it can lock people out or change behaviour; it then needs `--allow-risky`.
- A good fix is idempotent: running it twice leaves the same state.

## 4. Test it

Evaluator test with canned output:

```python
from fleetguard.transport import FakeTransport
from fleetguard.scan import run_check
assert run_check(FakeTransport({"find /var": "0\n"}), chk)["status"] == "PASS"
```

Fix test: subclass `tests.helpers.SandboxCase`, write the file with `self.write(...)`, call `remediate.apply_fix(self.host, chk, self.store)`, assert the new content, then `remediate.rollback(...)` and assert the old content. See `tests/test_checks_fix.py`.
