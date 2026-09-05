# ParseZeekLogs

Read [Zeek](https://zeek.org) network security monitor logs into typed Python
records, convert them to JSON or CSV, map them to Elastic Common Schema, and
load them into Elasticsearch.

[![Build](https://github.com/dgunter/ParseZeekLogs/actions/workflows/build.yml/badge.svg)](https://github.com/dgunter/ParseZeekLogs/actions/workflows/build.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=dgunter_ParseZeekLogs&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=dgunter_ParseZeekLogs)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=dgunter_ParseZeekLogs&metric=coverage)](https://sonarcloud.io/summary/new_code?id=dgunter_ParseZeekLogs)

Both Zeek output formats are handled by the same reader: the default
tab-separated logs, whose `#fields`/`#types` header drives full type
conversion, and JSON logs (`LogAscii::use_json=T`). Gzip-compressed files and
concatenated rotated logs work too.

## Install

Requires Python 3.10 or newer. The core package has no dependencies.

```bash
pip install parsezeeklogs
```

Add the Elasticsearch loader (client 9.x, for Elasticsearch 8 and 9):

```bash
pip install 'parsezeeklogs[elasticsearch]'
```

## Command line

```
parsezeeklogs json   FILE... [-o OUT] [--ecs] [-f FIELDS] [--safe-headers] [-m JSON] [--time-format iso]
parsezeeklogs csv    FILE... [-o OUT] [-f FIELDS] [--no-header]
parsezeeklogs fields FILE
parsezeeklogs elk    FILE... URL [-i INDEX] [--ecs] [--create-index] [auth/TLS options]
```

Convert a log to JSON lines, or to CSV with chosen columns:

```bash
parsezeeklogs json conn.log -o conn.jsonl
```

```bash
parsezeeklogs csv conn.log -f ts,id.orig_h,id.orig_p,id.resp_h,id.resp_p,duration -o conn.csv
```

List a log's fields with their Zeek types:

```bash
parsezeeklogs fields dns.log
```

Load logs into Elasticsearch, creating the index with a suitable mapping:

```bash
parsezeeklogs elk conn.log dns.log http.log http://localhost:9200 -i zeek --create-index
```

Same, but as Elastic Common Schema documents against a secured cluster:

```bash
parsezeeklogs elk *.log https://es.example.com:9200 -i zeek-ecs --ecs --create-index --api-key "$ES_API_KEY" --ca-certs ca.pem
```

Options shared by `json`, `csv` and `elk`:

| Option | Purpose |
| --- | --- |
| `-f`, `--fields A,B,...` | Keep only these fields |
| `--safe-headers` | Rewrite dots in field names to underscores (`id.orig_h` becomes `id_orig_h`) |
| `-m`, `--meta JSON` | Merge this object into every record |
| `--time-format iso` | Emit `time` values as ISO-8601 instead of epoch seconds |
| `--ecs` (`json`, `elk`) | Produce Elastic Common Schema documents |

Elasticsearch options for `elk`: `-i/--index`, `-s/--bulk-size`,
`--create-index`, `-u/--user`, `-p/--password` (prompted when omitted),
`--api-key`, `--ca-certs`, `-k/--insecure`, `--timeout`. Exit status is 1 when
any bulk item failed or the cluster was unreachable. Malformed lines are
skipped and counted, not fatal.

## Python API

```python
from parsezeeklogs import ZeekLog, read_zeek

for rec in read_zeek("conn.log"):
    print(rec["ts"], rec["id.orig_h"], rec["id.resp_p"], rec["duration"])

with ZeekLog("dns.log", fields=["ts", "query", "answers"], time_format="iso") as log:
    print(log.path, log.types)  # "dns", {"ts": "time", "query": "string", ...}
    records = list(log)
    print(log.skipped)  # malformed lines that were reported and skipped
```

Values arrive typed. Zeek `count`, `int` and `port` become `int`; `double`,
`interval` and `time` become `float`; `bool` becomes `bool`; `set[...]` and
`vector[...]` become lists; unset (`-`) is `None`; empty is `""` or `[]`;
Zeek's `\xHH` escapes are decoded. Helpers `to_json`, `write_json_lines` and
`write_csv` serialise records.

### Elastic Common Schema

`to_ecs(record, path)` returns an ECS document laid out like the Filebeat Zeek
module: `source.*`, `destination.*`, `network.*`, `event.*`, `dns.*`, `tls.*`,
`file.*`, `user.*` and so on, with everything else under `zeek.<log>.*` and the
Zeek `uid` in `zeek.session_id` and `event.id`. Community ID flow hashes,
connection state messages, `network.direction`, DNS answers, TLS versions and
certificate subjects are derived the same way the module's ingest pipelines do.

```python
from parsezeeklogs import read_zeek, to_ecs

for rec in read_zeek("conn.log"):
    doc = to_ecs(rec, "conn", {"observer": {"name": "sensor-1"}})
    # doc["source"]["ip"], doc["event"]["duration"] (nanoseconds), doc["network"]["community_id"], ...
```

Every emitted field is coerced to its ECS or Beats type (`long`, `boolean`,
`ip`, `date`, array fields as lists), and `--create-index --ecs` builds the
index mapping from the same table, so documents and mapping always agree. The
tables come from ECS 9.5.0 and Filebeat 9.5.3; `scripts/build_ecs_tables.py`
regenerates them for newer releases. GeoIP, ASN and user-agent enrichment
and public-suffix based `dns.question.registered_domain` are not reproduced,
as they need external databases.

### Elasticsearch loader

```python
from parsezeeklogs.elastic import ZeekToElk, ensure_index, make_client

es = make_client("https://es.example.com:9200", api_key="...", ca_certs="ca.pem")
ensure_index(es, "zeek-ecs", ecs=True)
result = ZeekToElk(es, index="zeek-ecs", ecs=True, metadata={"observer.name": "sensor-1"}).load(
    "conn.log"
)
print(result.indexed, result.failed, result.skipped)
```

Without `ecs=True` documents keep Zeek's field names and gain `@timestamp`
(from `ts`) and `@path` (the log type); the default mapping types `@timestamp`
as a date and `id.orig_h`/`id.resp_h` as `ip`.

### 2.x compatibility

The old iterator still works and returns JSON strings, CSV rows, or dicts:

```python
from parsezeeklogs import ParseZeekLogs

for line in ParseZeekLogs("conn.log", output_format="json", safe_headers=True):
    print(line)
```

`ParseZeekLogs.batch_to_elk(...)` is kept as well. See
[CHANGELOG.md](CHANGELOG.md) for behaviour that changed in 3.0.

## Development

```bash
uv sync                                     # Python 3.14 environment with dev tools
uv run pytest                               # unit tests
docker compose up -d --wait                 # Elasticsearch 9.5 on localhost:9200
uv run pytest -m integration                # end-to-end tests against it
uv run ruff check . && uv run ruff format .
```

The corpus test runs the reader over every log Zeek 8.2.2 writes for the
[PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK) captures, in both
TSV and JSON form, and checks the two parse to the same records:

```bash
git clone --depth 1 https://github.com/sbousseaden/PCAP-ATTACK .cache/PCAP-ATTACK
scripts/generate_zeek_logs.sh .cache/PCAP-ATTACK .cache/zeek-logs   # needs Docker
uv run pytest -m samples
```

`tests/data/` holds a curated subset of that output plus the original 2018
sample `conn.log`; see the README there for provenance.

### Releasing

Bump `version` in `pyproject.toml` and `__version__` in
`parsezeeklogs/__init__.py`, note the release in `CHANGELOG.md`, merge, then
publish a GitHub release tagged `v<version>`. The Release workflow rebuilds,
checks the tag against the package version, and publishes to PyPI through
trusted publishing.

## Thanks

- [@geekscrapy](https://github.com/geekscrapy): bug fixes and the safe header feature
- [@fryguy04](https://github.com/fryguy04): the multi-file JSON example
- [@alpiquero](https://github.com/alpiquero): the boolean parsing fix
- [@glorello](https://github.com/glorello): packaging and column alignment fixes

## License

Apache License 2.0. See [LICENSE.txt](LICENSE.txt).
