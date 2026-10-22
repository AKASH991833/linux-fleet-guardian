"""INI inventory.

    [defaults]
    user = ops
    sudo = true

    [web1]
    address = 10.0.0.11

    [localhost]
    local = true
"""
import configparser

from .transport import LocalTransport, SSHTransport


def _bool(v):
    return str(v).strip().lower() in ("1", "true", "yes", "on")


class Host(object):
    def __init__(self, name, opts):
        self.name = name
        self.opts = opts

    def transport(self):
        o = self.opts
        if _bool(o.get("local", "false")):
            return LocalTransport(root=o.get("root", ""), sudo=_bool(o.get("sudo", "false")),
                                  name=self.name)
        return SSHTransport(self.name, o.get("address", self.name), user=o.get("user"),
                            port=o.get("port"), key=o.get("key"),
                            sudo=_bool(o.get("sudo", "false")))


def load(path):
    cp = configparser.ConfigParser()
    with open(path) as fh:
        cp.read_file(fh)
    defaults = dict(cp["defaults"]) if cp.has_section("defaults") else {}
    hosts = []
    for sec in cp.sections():
        if sec == "defaults":
            continue
        opts = dict(defaults)
        opts.update(dict(cp[sec]))
        hosts.append(Host(sec, opts))
    if not hosts:
        raise ValueError("inventory %s defines no hosts" % path)
    return hosts


def local_host():
    return Host("localhost", {"local": "true"})
