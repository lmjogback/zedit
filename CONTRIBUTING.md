# Contributing

## Development

```sh
uv sync
uv run zedit --help
uv run pytest                 # integration tests need BIND (named, nsupdate, dig); zedit itself does not
uv run ruff check . && uv run ruff format .
uv run mypy                   # type check src/
```
