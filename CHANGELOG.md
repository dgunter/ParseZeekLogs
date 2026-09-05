# Changelog

## 3.0.1 - 2026-09-05

### Changed

- Tests now cover every line and branch of the package: the type coercion
  helpers, the per-log post-processors' edge cases, the index mapping for
  every field shape, and the CLI and reader error paths.
- The ECS index mapping skips children of `flattened` fields, which
  Elasticsearch cannot map; the published field table has none, so the
  generated mapping is unchanged.
- Removed the unused `ZeekLog.field_types` property; use `ZeekLog.types`.

## 3.0.0 - 2026-09-05

Rewrite for current Python and Zeek. The 2.x `ParseZeekLogs` iterator still
works; everything else is new.

### Added

- `ZeekLog` / `read_zeek`: iterate any Zeek log as typed dicts. Every Zeek
  type is honoured: `count`/`int`/`port` become `int`, `double`/`interval`/
  `time` become `float`, `bool` becomes `bool`, `set[...]`/`vector[...]`
  become lists, unset is `None`, empty is `""` or `[]`, and `\xHH` escapes are
  decoded.
- JSON logs (`LogAscii::use_json=T`) are read by the same class (#5).
- Gzip-compressed logs, concatenated rotated logs with repeated headers, and
  custom separators are handled.
- `to_json`, `write_json_lines`, `write_csv` helpers.
- Elastic Common Schema output (`to_ecs`, `--ecs`): documents laid out like the
  Filebeat Zeek module, with Community ID, `network.direction`, connection
  state messages, DNS answers, TLS versions and certificate subjects derived
  the same way. Field types follow ECS 9.5.0 and Filebeat 9.5.3, and
  `--create-index --ecs` builds the index mapping from the same table.
  `scripts/build_ecs_tables.py` regenerates the tables.
- `parsezeeklogs` console script with `json`, `csv`, `fields` and `elk`
  subcommands, replacing the example scripts.
- Elasticsearch loader rebuilt on the 9.x client with `--user`/`--password`,
  `--api-key`, `--ca-certs`, `--insecure` and `--create-index`. Documents gain
  `@timestamp` and `@path`; `id.orig_h`/`id.resp_h` are mapped as `ip`.
- Test suite: unit tests, integration tests against Elasticsearch 9 in Docker,
  and a corpus check that parses the TSV and JSON logs Zeek 8.2.2 writes for
  every capture in PCAP-ATTACK and verifies they agree record for record.
  `scripts/generate_zeek_logs.sh` rebuilds that corpus.
- GitHub Actions CI, SonarCloud analysis, and a release workflow that
  publishes to PyPI through trusted publishing.

### Changed

- Requires Python 3.10+. Python 2 support is gone.
- Elasticsearch is an optional extra: `pip install 'parsezeeklogs[elasticsearch]'`.
  The core package has no dependencies.
- Booleans parse correctly (`T`/`F`); previously every bool was `True` (#7,
  PR #8 by @alpiquero).
- `time` and `int` fields are numbers, not strings.
- In the compatibility iterator, unset values are omitted from JSON output and
  written as empty CSV cells; 2.x deleted unset numeric keys, which misaligned
  CSV columns.
- `ParseZeekLogs.batch_to_elk` returns a `LoadResult` and no longer sends
  `_type`, which Elasticsearch 8+ rejects.
- License changed from MIT to Apache 2.0.

### Removed

- `setup.py`; packaging is `pyproject.toml`.
- `examples/conn.log` moved to `tests/data/conn_2018.log`.

## 2.0.1

Last release of the single-module version, with `setup.py` (PR #10) and the
trailing-tab fix (PR #9) from @glorello.
