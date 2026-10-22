"""Run shell commands on the local machine or over SSH.

Every probe and fix is a plain POSIX shell snippet, so the same check works
locally and remotely. FG_ROOT (default empty) prefixes file paths so tests can
run real fixes inside a throw-away directory tree instead of the live system.
"""
import os
import shlex
import subprocess


class Result(object):
    def __init__(self, rc, out, err):
        self.rc = rc
        self.out = out
        self.err = err


class Transport(object):
    name = "base"

    def run(self, cmd, timeout=30, stdin=None):
        raise NotImplementedError


class LocalTransport(Transport):
    def __init__(self, root="", sudo=False, name="local"):
        self.root = root
        self.sudo = sudo
        self.name = name

    def run(self, cmd, timeout=30, stdin=None):
        env = dict(os.environ)
        env["FG_ROOT"] = self.root
        env["LC_ALL"] = "C"
        argv = ["sh", "-c", cmd]
        if self.sudo and os.geteuid() != 0:
            argv = ["sudo", "-n", "env", "FG_ROOT=" + self.root] + argv
        try:
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               input=stdin, env=env, timeout=timeout,
                               universal_newlines=True)
            return Result(p.returncode, p.stdout, p.stderr)
        except subprocess.TimeoutExpired:
            return Result(124, "", "timeout after %ss" % timeout)
        except OSError as e:
            return Result(127, "", str(e))


class SSHTransport(Transport):
    def __init__(self, name, address, user=None, port=None, key=None, sudo=False,
                 extra_opts=None):
        self.name = name
        self.address = address
        self.user = user
        self.port = port
        self.key = key
        self.sudo = sudo
        self.extra_opts = extra_opts or []

    def _argv(self, cmd):
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
        argv += list(self.extra_opts)
        if self.port:
            argv += ["-p", str(self.port)]
        if self.key:
            argv += ["-i", self.key]
        target = "%s@%s" % (self.user, self.address) if self.user else self.address
        remote = "sh -c " + shlex.quote(cmd)
        if self.sudo:
            remote = "sudo -n " + remote
        return argv + [target, remote]

    def run(self, cmd, timeout=30, stdin=None):
        try:
            p = subprocess.run(self._argv(cmd), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, input=stdin, timeout=timeout,
                               universal_newlines=True)
            return Result(p.returncode, p.stdout, p.stderr)
        except subprocess.TimeoutExpired:
            return Result(124, "", "timeout after %ss" % timeout)
        except OSError as e:
            return Result(127, "", str(e))


class FakeTransport(Transport):
    """Canned answers for unit tests: maps a substring of the command to output."""

    def __init__(self, answers=None, name="fake"):
        self.answers = answers or {}
        self.name = name
        self.calls = []

    def run(self, cmd, timeout=30, stdin=None):
        self.calls.append(cmd)
        for key, val in self.answers.items():
            if key in cmd:
                if isinstance(val, Result):
                    return val
                return Result(0, val, "")
        return Result(0, "", "")
