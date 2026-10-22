"""Example Python plugin: flag hosts that run without any swap configured.

Copy this file, change the id/probe/evaluator, and point --plugins at the directory.
"""


def register(registry, api):
    def evaluate(out):
        total = int(out.strip() or 0)
        return (api.PASS if total > 0 else api.FAIL), "swap total %d kB" % total

    registry.add(api.Check(
        "CUS-100", "Swap space is configured", "low", "Custom",
        "awk '/^SwapTotal:/{print $2}' /proc/meminfo", evaluate, tags=("custom",)))
