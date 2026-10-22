# Contributing

1. Fork, branch, and keep each change focused.
2. `make test` and `make lint` must pass. CI also runs the suite on ten Linux distributions and builds packages.
3. New check? Read [docs/WRITING_CHECKS.md](docs/WRITING_CHECKS.md). Add a unit test with canned probe output, and for a fix, a sandbox test that applies it and rolls it back. Run `make checks-doc`.
4. Keep it standard-library-only and compatible with Python 3.6 (RHEL 8). Avoid the walrus operator, dataclasses and `subprocess.run(capture_output=...)`.
5. Be honest in docs: say what was verified and how.
