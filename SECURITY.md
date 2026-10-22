# Security policy

## Reporting a problem

Open a private security advisory on GitHub (Security tab, "Report a vulnerability"). Please do not open a public issue for anything that could hurt users before it is fixed.

## Design choices that matter for security

- **Dry run by default.** `fleetguard fix` changes nothing without `--apply`. Fixes that can lock you out (for example disabling SSH password login) additionally need `--allow-risky`.
- **Every change is journalled and reversible.** Files are snapshotted before a fix, the check is re-run afterwards, and a fix that does not verify is rolled back automatically.
- **No agent on the target.** Remote hosts are reached over plain `ssh` with `BatchMode`; nothing is installed or left running there. Guardian never stores passwords. Use SSH keys and, for root-only files, `sudo -n` with a narrow sudoers rule.
- **Web panel is read-only and loopback by default.** Binding to a non-loopback address is refused unless a bearer token is set. The panel sends strict headers and escapes all output. Put TLS in front of it (reverse proxy) if you expose it.
- **Python plugins run with your privileges.** Only pass `--plugins` directories you trust. JSON plugins contain no code.
- **Backup restore-tests reject unsafe archives** (path traversal, hard links, escaping symlinks, device nodes) and verify the archive checksum before extracting.
- **Drills never touch the source.** The drill copies data to a scratch directory, destroys that copy, and restores into it.

## Known limits

- Guardian is an audit and hygiene tool, not an intrusion detection system and not a certified CIS-CAT scanner.
- Check logic is probe-based (shell output matching). A host that lies to its own shell can fool it.
- The `FG_ROOT` environment variable relocates file paths for testing. Do not set it in production.
