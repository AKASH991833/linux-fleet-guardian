# Operations guide

## Daily rhythm that works for a small fleet

| Frequency | Command | Why |
|---|---|---|
| Hourly | `fleetguard scan -i inv.ini --drift --fail-on high` | Catch regressions fast. Exit 2 or 3 can page you. |
| Every 5 minutes | `fleetguard perf check -i inv.ini` | Builds the baseline and flags spikes. |
| Daily | `fleetguard backup restore-test --dest /backup --rpo 90000 --rto 600` | A backup you never restore is a hope. |
| Monthly | `fleetguard drill --source /srv/app --report drill-$(date +%F).md` | Measured RTO for your runbook. |
| On demand | `fleetguard timeline --hours 6 --auth-log /var/log/auth.log` | Incident write-up. |

Example crontab:

```
0 * * * *    fleetguard scan -i /etc/fleetguard/inventory.ini --drift --fail-on high || mail -s "Guardian: regression" ops@example.com < /dev/null
*/5 * * * *  fleetguard perf check -i /etc/fleetguard/inventory.ini
```

## First rollout on a real host

1. `fleetguard scan` and read it. Nothing changes.
2. `fleetguard fix` (dry run). Read every line.
3. Keep a second SSH session open, then `fleetguard fix --apply --check SSH-001`.
4. Only then widen. `SSH-004` (key-only login) needs `--allow-risky`; confirm your key works first.
5. `fleetguard scan --save-baseline` to lock in the good state.

## Remote hosts

Use a dedicated account with an SSH key. For root-only files set `sudo = true` and allow only what Guardian needs:

```
guardian ALL=(root) NOPASSWD: /bin/sh -c *
```

That rule is broad: it lets the account run any command as root. If that is too much, leave `sudo` off; checks that need root report SKIP rather than guessing.

## Choosing RPO and RTO

RPO is how much data you can afford to lose (maximum backup age). RTO is how long you can be down (maximum restore time). Set them from the business, then let `restore-test` and `drill` tell you whether you meet them.

## Backing up Guardian itself

State lives in `FLEETGUARD_STATE` (`/var/lib/fleetguard` for root). The `journal/` directory holds snapshots of files changed by fixes; keep it until you are happy with the change.
