# Notes for coding agents

Build, run and lint commands are under "Development" in README.md. This file
lists what the code doesn't tell you.

## Tests

- `uv run pytest -rs` runs unit and integration tests. The integration tests
  start a real BIND and need `named`, `nsupdate`, `tsig-keygen` and `dig`
  (also looked for in `/usr/sbin`). If any is missing, the whole module is
  skipped, so check the skip summary: a green run may not have touched BIND.
  With `ZEDIT_REQUIRE_INTEGRATION=1` (set in CI) a skip is a failure instead,
  and if named doesn't start, the end of its log is in the message.
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
  `src/zedit/session.py` (if it should carry over to `--resume`) and into
  `test_resume_command_keeps_the_options`. Nothing catches a forgotten one.

## dnspython

`zonefile._Reader` overrides the private `dns.zonefile.Reader._eat_line()` and
reads `last_name`, to report records outside the zone.
`test_dnspython_reader_hook` guards this. Check it before raising the `dnspython<3` bound.

## Releases

A release is its own commit on `main`, made after the changes it releases have
been merged and tested; never put it on a topic branch with other changes.

1. Rename `## Unreleased` to `## X.Y.Z - YYYY-MM-DD`.
2. Set `version` in `pyproject.toml` and run `uv lock`.
3. Commit as "Release X.Y.Z" and tag `vX.Y.Z`.

CI's `version` job fails if these disagree, but only after a push. Tagging and
pushing are left to the maintainer.

## CI

The actions in `.github/workflows/ci.yml` are pinned by commit SHA with the
version as a comment (`@<sha> # v7.0.1`). Keep that form when changing them;
Dependabot (`.github/dependabot.yml`) proposes updates weekly. Check a SHA with
`gh api repos/OWNER/ACTION/commits/TAG -q .sha`.

CI runs on pushes to `main`, on `v*` tags and on pull requests. To run it on
another branch without a pull request: `gh workflow run CI --ref BRANCH`.
