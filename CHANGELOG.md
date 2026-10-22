# Changelog

## 0.1.0 - 2026-10-23

First release.

- 24 CIS-style checks (SSH, kernel and network parameters, file permissions, accounts, services, logging).
- Plugin system: declarative JSON checks and Python plugins.
- Drift detection against a saved baseline, with regression exit code for CI and cron.
- Reversible fixes: dry run by default, file snapshot, verification, automatic rollback, journal, manual rollback.
- Backup creation, restore-test (hash-verified, RPO/RTO aware) and DR drill on a scratch copy.
- Performance baseline and robust-statistics anomaly detection.
- Incident timeline (Markdown/HTML) with failed-SSH-login burst detection from auth logs.
- Read-only web panel and Prometheus metrics; Grafana dashboard and alert rules.
- Packaging: .deb, .rpm, systemd unit, Ansible role.
