"""Check and fix model plus the built-in CIS-style rule set.

The `cis` field names the CIS Benchmark *topic* a rule is modelled on. It is not a
certified CIS-CAT result and does not quote benchmark numbering.
"""
import re

PASS, FAIL, SKIP, ERROR = "PASS", "FAIL", "SKIP", "ERROR"
SEVERITIES = ("low", "medium", "high")
NA = "__NA__"


class Fix(object):
    """A reversible remediation.

    files  : paths (relative to FG_ROOT) that are snapshotted before `script` runs
    script : POSIX sh; may use $FG_ROOT. Must exit non-zero on failure.
    post   : optional command run only on a live system (FG_ROOT empty), e.g. reload
    risky  : needs --allow-risky (can lock you out or change behaviour)
    """

    def __init__(self, description, files, script, post=None, risky=False):
        self.description = description
        self.files = list(files)
        self.script = script
        self.post = post
        self.risky = risky


class Check(object):
    def __init__(self, id, title, severity, cis, probe, evaluate, fix=None, tags=()):
        assert severity in SEVERITIES
        self.id = id
        self.title = title
        self.severity = severity
        self.cis = cis
        self.probe = probe
        self.evaluate = evaluate
        self.fix = fix
        self.tags = tuple(tags)


class Registry(object):
    def __init__(self):
        self._checks = {}

    def add(self, check):
        if check.id in self._checks:
            raise ValueError("duplicate check id %s" % check.id)
        self._checks[check.id] = check

    def all(self):
        return [self._checks[k] for k in sorted(self._checks)]

    def get(self, cid):
        return self._checks.get(cid)

    def select(self, ids=None, tags=None):
        out = []
        for c in self.all():
            if ids and c.id not in ids:
                continue
            if tags and not set(tags) & set(c.tags):
                continue
            out.append(c)
        return out


# ---------- evaluators ----------

def _is_na(out):
    return out.strip() == NA


def ev_equals(expected):
    def ev(out):
        v = out.strip()
        if _is_na(out):
            return SKIP, "not applicable on this host"
        if v == "":
            return FAIL, "not set"
        return (PASS if v == expected else FAIL), v
    return ev


def ev_int_max(limit):
    def ev(out):
        v = out.strip()
        if _is_na(out):
            return SKIP, "not applicable on this host"
        if not re.match(r"^-?\d+$", v):
            return FAIL, v or "not set"
        return (PASS if int(v) <= limit else FAIL), v
    return ev


def ev_int_min(limit):
    def ev(out):
        v = out.strip()
        if _is_na(out):
            return SKIP, "not applicable on this host"
        if not re.match(r"^-?\d+$", v):
            return FAIL, v or "not set"
        return (PASS if int(v) >= limit else FAIL), v
    return ev


def ev_empty_is_pass(what):
    """Probe lists offenders; empty output is compliant."""
    def ev(out):
        if _is_na(out):
            return SKIP, "not applicable on this host"
        lines = [l for l in out.splitlines() if l.strip()]
        if not lines:
            return PASS, "none"
        return FAIL, "%s: %s" % (what, ", ".join(lines[:10]))
    return ev


def ev_mode(max_mode, owners):
    """Probe prints `<octal mode> <owner>:<group>`."""
    def ev(out):
        v = out.strip()
        if _is_na(out) or v == "":
            return SKIP, "file not present"
        parts = v.split()
        if len(parts) != 2:
            return ERROR, "unexpected probe output: %r" % v
        mode, own = parts
        try:
            m = int(mode, 8)
        except ValueError:
            return ERROR, "bad mode %r" % mode
        if m & ~max_mode & 0o7777:
            return FAIL, "mode %s owner %s (want <= %o)" % (mode, own, max_mode)
        if own not in owners:
            return FAIL, "mode %s owner %s (want %s)" % (mode, own, "/".join(owners))
        return PASS, "mode %s owner %s" % (mode, own)
    return ev


def ev_active(out):
    v = out.strip()
    if v == NA or v == "":
        return SKIP, "cannot determine (no systemd?)"
    return (PASS if v == "active" else FAIL), v


# ---------- builders ----------

def sshd_value_probe(key):
    return (
        'for f in "$FG_ROOT"/etc/ssh/sshd_config.d/*.conf "$FG_ROOT/etc/ssh/sshd_config"; do '
        '[ -r "$f" ] && grep -Ei "^[[:space:]]*%s[[:space:]]" "$f"; done '
        "| head -1 | awk '{print tolower($2)}'" % key
    )


def sshd_fix(key, value, risky=False):
    script = (
        'f="$FG_ROOT/etc/ssh/sshd_config"; [ -f "$f" ] || exit 1; '
        'if grep -Eiq "^[[:space:]]*#?[[:space:]]*%(k)s[[:space:]]" "$f"; then '
        'sed -i -E "s/^[[:space:]]*#?[[:space:]]*%(k)s[[:space:]].*/%(k)s %(v)s/" "$f"; '
        'else printf "\\n%(k)s %(v)s\\n" >> "$f"; fi; '
        'if [ -z "$FG_ROOT" ] && command -v sshd >/dev/null 2>&1; then sshd -t -f "$f" || exit 1; fi'
        % {"k": key, "v": value}
    )
    return Fix("Set '%s %s' in /etc/ssh/sshd_config, validate with sshd -t" % (key, value),
               ["/etc/ssh/sshd_config"], script,
               post="systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true",
               risky=risky)


def sysctl_check(cid, title, key, value, severity, cis):
    probe = "sysctl -n %s 2>/dev/null || echo %s" % (key, NA)
    script = (
        'mkdir -p "$FG_ROOT/etc/sysctl.d"; '
        'printf "%s = %s\\n" >> "$FG_ROOT/etc/sysctl.d/99-fleetguard.conf"' % (key, value)
    )
    fx = Fix("Persist '%s = %s' in /etc/sysctl.d/99-fleetguard.conf and apply" % (key, value),
             ["/etc/sysctl.d/99-fleetguard.conf"], script,
             post="sysctl -w %s=%s >/dev/null" % (key, value))
    return Check(cid, title, severity, cis, probe, ev_equals(str(value)), fix=fx,
                 tags=("kernel", "network") if key.startswith("net.") else ("kernel",))


def mode_check(cid, title, path, max_mode, owners, severity, cis):
    probe = (
        'p="$FG_ROOT%s"; [ -e "$p" ] && stat -c "%%a %%U:%%G" "$p" || echo %s' % (path, NA)
    )
    fix = Fix("chmod %o and chown root on %s" % (max_mode, path), [path],
              'p="$FG_ROOT%s"; chmod %o "$p"; chown root "$p" 2>/dev/null || true' % (path, max_mode))
    return Check(cid, title, severity, cis, probe, ev_mode(max_mode, owners), fix=fix,
                 tags=("filesystem",))


def _builtin():
    reg = Registry()
    ssh = "SSH Server Configuration"
    for cid, key, val, title, sev, risky in [
        ("SSH-001", "PermitRootLogin", "no", "SSH root login is disabled", "high", False),
        ("SSH-002", "PermitEmptyPasswords", "no", "SSH rejects empty passwords", "high", False),
        ("SSH-003", "X11Forwarding", "no", "SSH X11 forwarding is disabled", "low", False),
        ("SSH-004", "PasswordAuthentication", "no",
         "SSH password authentication is disabled (key-only)", "medium", True),
    ]:
        reg.add(Check(cid, title, sev, ssh, sshd_value_probe(key), ev_equals(val),
                      fix=sshd_fix(key, val, risky), tags=("ssh",)))
    reg.add(Check("SSH-005", "SSH MaxAuthTries is 4 or less", "medium", ssh,
                  sshd_value_probe("MaxAuthTries"), ev_int_max(4),
                  fix=sshd_fix("MaxAuthTries", 4), tags=("ssh",)))

    net = "Network Configuration"
    reg.add(sysctl_check("NET-001", "IP forwarding is disabled (unless this host routes)",
                         "net.ipv4.ip_forward", 0, "medium", net))
    reg.add(sysctl_check("NET-002", "TCP SYN cookies are enabled",
                         "net.ipv4.tcp_syncookies", 1, "medium", net))
    reg.add(sysctl_check("NET-003", "ICMP redirects are not accepted",
                         "net.ipv4.conf.all.accept_redirects", 0, "medium", net))
    reg.add(sysctl_check("NET-004", "Packet redirect sending is disabled",
                         "net.ipv4.conf.all.send_redirects", 0, "low", net))
    reg.add(sysctl_check("NET-005", "Source route packets are not accepted",
                         "net.ipv4.conf.all.accept_source_route", 0, "medium", net))
    reg.add(sysctl_check("KRN-001", "Address space layout randomization is full",
                         "kernel.randomize_va_space", 2, "medium", "Kernel Parameters"))
    reg.add(sysctl_check("KRN-002", "Core dumps of setuid programs are restricted",
                         "fs.suid_dumpable", 0, "low", "Kernel Parameters"))

    fs = "File Permissions"
    reg.add(mode_check("FS-001", "/etc/passwd is 644 owned by root", "/etc/passwd", 0o644,
                       ("root:root",), "medium", fs))
    reg.add(mode_check("FS-002", "/etc/shadow is not readable by others", "/etc/shadow", 0o640,
                       ("root:root", "root:shadow"), "high", fs))
    reg.add(mode_check("FS-003", "/etc/group is 644 owned by root", "/etc/group", 0o644,
                       ("root:root",), "medium", fs))
    reg.add(mode_check("FS-004", "/etc/gshadow is not readable by others", "/etc/gshadow", 0o640,
                       ("root:root", "root:shadow"), "high", fs))
    reg.add(mode_check("FS-005", "sshd_config is 600 owned by root", "/etc/ssh/sshd_config",
                       0o600, ("root:root",), "medium", fs))

    acc = "User Accounts and Environment"
    reg.add(Check("ACC-001", "No account has an empty password", "high", acc,
                  'f="$FG_ROOT/etc/shadow"; [ -r "$f" ] && awk -F: \'($2==""){print $1}\' "$f" '
                  '|| echo %s' % NA, ev_empty_is_pass("empty password"), tags=("accounts",)))
    reg.add(Check("ACC-002", "Only root has UID 0", "high", acc,
                  'awk -F: \'($3==0 && $1!="root"){print $1}\' "$FG_ROOT/etc/passwd"',
                  ev_empty_is_pass("extra UID 0"), tags=("accounts",)))
    reg.add(Check("ACC-003", "No duplicate UIDs", "medium", acc,
                  'cut -d: -f3 "$FG_ROOT/etc/passwd" | sort | uniq -d',
                  ev_empty_is_pass("duplicate UID"), tags=("accounts",)))
    reg.add(Check("ACC-004", "Password maximum age is 365 days or less", "medium", acc,
                  "awk '/^PASS_MAX_DAYS/{print $2}' \"$FG_ROOT/etc/login.defs\" 2>/dev/null",
                  ev_int_max(365),
                  fix=Fix("Set PASS_MAX_DAYS 365 in /etc/login.defs", ["/etc/login.defs"],
                          'f="$FG_ROOT/etc/login.defs"; [ -f "$f" ] || exit 1; '
                          'if grep -Eq "^PASS_MAX_DAYS" "$f"; then '
                          'sed -i -E "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/" "$f"; '
                          'else printf "PASS_MAX_DAYS   365\\n" >> "$f"; fi'),
                  tags=("accounts",)))

    svc = "Services"
    reg.add(Check("SVC-001", "Nothing listens on telnet (23)", "high", svc,
                  "command -v ss >/dev/null 2>&1 || { echo %s; exit 0; }; "
                  "ss -ltn 2>/dev/null | awk '$4 ~ /:23$/{print $4}'" % NA,
                  ev_empty_is_pass("listening"), tags=("services",)))
    reg.add(Check("SVC-002", "Nothing listens on plain FTP (21)", "medium", svc,
                  "command -v ss >/dev/null 2>&1 || { echo %s; exit 0; }; "
                  "ss -ltn 2>/dev/null | awk '$4 ~ /:21$/{print $4}'" % NA,
                  ev_empty_is_pass("listening"), tags=("services",)))
    reg.add(Check("LOG-001", "A system logging service is active", "medium",
                  "Logging and Auditing",
                  "command -v systemctl >/dev/null 2>&1 || { echo %s; exit 0; }; "
                  "systemctl is-active rsyslog 2>/dev/null | grep -qx active && echo active "
                  "|| systemctl is-active systemd-journald 2>/dev/null || echo inactive" % NA,
                  ev_active, tags=("logging",)))
    return reg


def builtin_registry():
    return _builtin()
