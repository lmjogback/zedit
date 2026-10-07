# Notes for coding agents

Build, run and lint commands are under "Development" in README.md. This file
lists what the code doesn't tell you.

## Tests

- `uv run pytest -rs` runs unit and integration tests. The integration tests
  start a real BIND and need `named`, `nsupdate`, `tsig-keygen` and `dig`
  (also looked for in `/usr/sbin`). If any is missing, the whole module is
  skipped, so check the skip summary: a green run may not have touched BIND.
- To test with the oldest allowed dependency versions, as CI's `lowest` job
  does, run
  `uv run --isolated --python 3.10 --resolution lowest-direct pytest tests/test_logic.py`.
  Without `--isolated` it rewrites `uv.lock` and downgrades `.venv`; if that
  happened, `git restore uv.lock && uv sync --locked` puts both back.

## When you change behaviour

- Add a line under `## Unreleased` at the top of CHANGELOG.md.
- Keep README.md in step: options table, exit statuses, "Behaviour" section;
  and docs/signaling.md for anything about CDS/CDNSKEY or signals.
- A new command-line option also goes into `resume_command()` in
  `src/zedit/cli.py` (if it should carry over to `--resume`) and into
  `test_resume_command_keeps_the_options`. Nothing catches a forgotten one.

## dnspython

`cli._Reader` overrides the private `dns.zonefile.Reader._eat_line()` and reads
`last_name`, to report records outside the zone. `test_dnspython_reader_hook`
guards this. Check it before raising the `dnspython<3` bound.

## Releases

1. Rename `## Unreleased` to `## X.Y.Z - YYYY-MM-DD`.
2. Set `version` in `pyproject.toml` and run `uv lock`.
3. Commit as "Release X.Y.Z" and tag `vX.Y.Z`.

CI's `version` job fails if these disagree, but only after a push. Tagging and
pushing are left to the maintainer.
