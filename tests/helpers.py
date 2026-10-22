import os
import shutil
import tempfile
import unittest

from fleetguard import inventory
from fleetguard.store import Store


class SandboxCase(unittest.TestCase):
    """A fake root filesystem so real fixes run for real, without touching the system."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="fg-root-")
        self.state = tempfile.mkdtemp(prefix="fg-state-")
        self.store = Store(self.state)
        self.host = inventory.Host("sandbox", {"local": "true", "root": self.root})
        for d in ("etc/ssh/sshd_config.d", "etc/sysctl.d"):
            os.makedirs(os.path.join(self.root, d))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.rmtree(self.state, ignore_errors=True)

    def write(self, rel, text, mode=0o644):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text)
        os.chmod(p, mode)
        return p

    def read(self, rel):
        with open(os.path.join(self.root, rel)) as fh:
            return fh.read()
