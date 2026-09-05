# ParseZeekLogs

Read [Zeek](https://zeek.org) network security monitor logs into typed Python
records, then do something useful with them: filter them like `zeek-cut`,
convert them to JSON or CSV, drop them into a pandas DataFrame for a threat
hunt, or load them into Elasticsearch as Elastic Common Schema documents.

[![PyPI](https://img.shields.io/pypi/v/parsezeeklogs)](https://pypi.org/project/parsezeeklogs/)
[![Build](https://github.com/dgunter/ParseZeekLogs/actions/workflows/build.yml/badge.svg)](https://github.com/dgunter/ParseZeekLogs/actions/workflows/build.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=dgunter_ParseZeekLogs&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=dgunter_ParseZeekLogs)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=dgunter_ParseZeekLogs&metric=coverage)](https://sonarcloud.io/summary/new_code?id=dgunter_ParseZeekLogs)

```bash
pip install parsezeeklogs
```

```python
from parsezeeklogs import read_zeek

for conn in read_zeek("conn.log"):
    if conn["duration"] and conn["duration"] > 600 and conn["local_resp"] is False:
        print(conn["ts"], conn["id.orig_h"], "->", conn["id.resp_h"], conn["id.resp_p"], conn["service"])
```

Every value arrives as the right Python type: ports and counts are `int`,
durations and timestamps are `float`, `T`/`F` are `bool`, sets and vectors
are lists, and Zeek's `-` (unset) is `None`. No dependencies. Python 3.10+.

## Why this exists

ParseBroLogs started in January 2018 after one too many rewrites of the same
Bro log parser for one-off analysis scripts. The goals were modest: a
lightweight package with no dependencies, a way to pick fields the way
`bro-cut` does, and output that was equally at home in a Jupyter notebook and
in a CSV opened by an analyst in Excel. It went on to power the network
analysis in the *Threat Hunting with Python* series, where Bro `http.log`,
`ntlm.log` and other logs were pulled into pandas to find Nmap scans by their
status-code behaviour and to audit administrator logons crossing from a
corporate subnet into a process control network.

Version 3.0 is a rewrite for today's stack. Zeek's TSV and JSON log formats
are both read by the same code, every Zeek type is converted faithfully, and
the output can be Elastic Common Schema documents laid out the way the
Filebeat Zeek module produces them. The original 2018 write-up is preserved in
[docs/blog-2018-parsebrologs.md](docs/blog-2018-parsebrologs.md).

## A short tour

### Reading logs

```python
from parsezeeklogs import ZeekLog

with ZeekLog("dns.log") as log:
    print(log.path)           # "dns"
    print(log.types["query"]) # "string"
    print(log.fields[:6])     # ['ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p']
    for rec in log:
        if rec["qtype_name"] == "TXT" and rec["answers"]:
            print(rec["query"], rec["answers"])
    print(log.skipped)        # malformed lines that were reported and skipped
```

The reader looks at the first line to decide whether it has a TSV log (a
`#separator` header) or a JSON log (`LogAscii::use_json=T`), so both work
without telling it which. Gzip-compressed files and concatenated rotated
logs, which repeat their header mid-file, are handled. Options:

| Option | Effect |
| --- | --- |
| `fields=[...]` | keep only these fields, like `zeek-cut` |
| `safe_headers=True` | `id.orig_h` becomes `id_orig_h`; handy for CSV headers and databases |
| `time_format="iso"` | emit `time` values as ISO-8601 strings instead of epoch floats |
| `meta={...}` | merge a dict into every record, for example the sensor name |
| `on_error=callback` | called with (line number, text, exception) for each skipped line |

### Hunting in a notebook

Records are plain dicts, so a DataFrame is one line away. This is the
user-agent stacking from part two of the hunting series, against Zeek 8
logs, without any of the manual tab-splitting the original notebook needed:

```python
import pandas as pd
from parsezeeklogs import read_zeek

http = pd.DataFrame(read_zeek("http.log", time_format="datetime"))

# Who is talking HTTP, and with what?
http["user_agent"].fillna("(none)").value_counts().head(10)

# Scanners hit URIs that do not exist: 404s per client per minute
errors = http[http["status_code"] >= 400]
errors.groupby([errors["ts"].dt.floor("min"), "id.orig_h"]).size().sort_values(ascending=False).head()
```

And the SMB audit from part three, on `ntlm.log`: privileged accounts
authenticating from the corporate subnet into the control network.

```python
ntlm = pd.DataFrame(read_zeek("ntlm.log"))
pivots = ntlm[
    ntlm["id.orig_h"].str.startswith("192.168.5.")
    & ntlm["id.resp_h"].str.startswith("192.168.6.")
    & (ntlm["username"].str.lower() == "administrator")
]
pivots[["ts", "id.orig_h", "id.resp_h", "username", "hostname", "domainname", "success"]]
```

### Converting logs

From the shell:

```bash
parsezeeklogs json conn.log dns.log -o zeek.jsonl
```

```bash
parsezeeklogs csv conn.log -f ts,id.orig_h,id.orig_p,id.resp_h,id.resp_p,duration -o conn.csv
```

```bash
parsezeeklogs fields ssl.log        # field name and Zeek type, one per line
```

From Python, `to_json`, `write_json_lines` and `write_csv` do the same for
any iterable of records.

### Elastic Common Schema

Add `--ecs` and the same records come out as ECS documents in the layout the
Filebeat Zeek module uses. Common fields become `source.*`, `destination.*`,
`network.*`, `event.*`, `dns.*`, `tls.*`, `file.*` and `user.*`; the rest
stays under `zeek.<log>.*`; the Zeek `uid` lands in `zeek.session_id` and
`event.id`.

```bash
parsezeeklogs json conn.log --ecs | head -1 | jq .
```

```json
{
  "@timestamp": "2020-07-20T22:34:18.733203+00:00",
  "event": {"kind": "event", "category": ["network"], "type": ["connection", "start"],
            "dataset": "zeek.connection", "duration": 31884000, "id": "CJioLj2aEkGc9R3T0b"},
  "source": {"ip": "192.168.56.101", "port": 5353, "bytes": 328, "packets": 4},
  "destination": {"ip": "224.0.0.251", "port": 5353, "bytes": 0, "packets": 0},
  "network": {"transport": "udp", "protocol": "dns", "direction": "internal",
              "bytes": 328, "packets": 4, "community_id": "1:ZtmuRe1iQygjfEmIgxoGU7wxP8E="},
  "related": {"ip": ["192.168.56.101", "224.0.0.251"]},
  "zeek": {"session_id": "CJioLj2aEkGc9R3T0b",
           "connection": {"state": "S0", "state_message": "Connection attempt seen, no reply.",
                          "history": "D", "local_orig": true, "local_resp": true}},
  "ecs": {"version": "9.5.0"}
}
```

Community ID flow hashes, `network.direction`, connection state messages,
DNS answers, TLS versions and certificate subjects are derived the same way
the module's ingest pipelines derive them. Every field is coerced to its ECS
or Beats type, so `event.duration` is an integer of nanoseconds, `dns.id` is
a string, `tls.established` is a boolean, and array fields are lists. The
tables come from ECS 9.5.0 and Filebeat 9.5.3; `scripts/build_ecs_tables.py`
regenerates them for newer releases. GeoIP, ASN and user-agent enrichment and
public-suffix based `dns.question.registered_domain` are not reproduced, as
they need external databases.

```python
from parsezeeklogs import read_zeek, to_ecs

for rec in read_zeek("conn.log"):
    doc = to_ecs(rec, "conn", {"observer": {"name": "sensor-1"}})
```

### Loading into Elasticsearch

```bash
pip install 'parsezeeklogs[elasticsearch]'
```

```bash
parsezeeklogs elk *.log https://es.example.com:9200 -i zeek-ecs --ecs --create-index --api-key "$ES_API_KEY" --ca-certs ca.pem
```

`--create-index` builds the index mapping from the same field table the
transform uses, so `source.ip` is an `ip` field you can query by CIDR and
`event.duration` is a `long` you can range over. Without `--ecs`, documents
keep Zeek's field names and gain `@timestamp` and `@path`. Authentication
options: `-u/--user` with `-p/--password` (prompted when omitted),
`--api-key`, `--ca-certs`, `-k/--insecure`. Exit status is 1 when any bulk
item failed or the cluster could not be reached.

```python
from parsezeeklogs.elastic import ZeekToElk, ensure_index, make_client

es = make_client("https://es.example.com:9200", api_key="...", ca_certs="ca.pem")
ensure_index(es, "zeek-ecs", ecs=True)
result = ZeekToElk(es, index="zeek-ecs", ecs=True, metadata={"observer.name": "sensor-1"}).load("conn.log")
print(result.indexed, result.failed, result.skipped)
```

### Still on 2.x?

The old iterator is still there and now returns correctly typed data:

```python
from parsezeeklogs import ParseZeekLogs

for line in ParseZeekLogs("conn.log", output_format="json", safe_headers=True):
    print(line)
```

`ParseZeekLogs.batch_to_elk(...)` is kept too. [CHANGELOG.md](CHANGELOG.md)
lists what changed, including the 2.x bugs that are now fixed: booleans were
always true, `time` and `int` fields were strings, and unset numeric fields
shifted CSV columns.

## Command reference

```
parsezeeklogs json   FILE... [-o OUT] [--ecs] [-f FIELDS] [--safe-headers] [-m JSON] [--time-format iso]
parsezeeklogs csv    FILE... [-o OUT] [-f FIELDS] [--no-header] [--safe-headers] [-m JSON]
parsezeeklogs fields FILE
parsezeeklogs elk    FILE... URL [-i INDEX] [-s BULK] [--ecs] [--create-index] [-m JSON]
                                 [-u USER] [-p PASS] [--api-key KEY] [--ca-certs PEM] [-k] [--timeout S]
```

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
TSV and JSON form, and checks that the two parse to the same records:

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

## Further reading

- [Simplifying Bro IDS Log Parsing with ParseBroLogs](docs/blog-2018-parsebrologs.md), the January 2018 announcement, recovered from the Wayback Machine.
- *Threat Hunting with Python* series: [part 2, Nmap behaviour in HTTP logs](https://www.dragos.com/blog/threat-hunting-with-python-part-2-detecting-nmap-behavior-with-bro-http-logs) (Dragos, still online), [part 3, taming SMB](https://web.archive.org/web/20190716204520/https://dgunter.com/2018/02/17/threat-hunting-with-python-and-bro-ids-part-3-taming-smb/) and [part 4, MS SQL historian traffic](https://web.archive.org/web/20190711052703/https://dgunter.com/2018/03/20/threat-hunting-with-python-part-4-examining-microsoft-sql-based-historian-traffic/) (archived). Notebooks are in [dgunter/Blog-Code](https://github.com/dgunter/Blog-Code).

## Thanks

- [@geekscrapy](https://github.com/geekscrapy): bug fixes, the safe header feature, and [bro2csv](https://github.com/geekscrapy/bro2csv)
- [@fryguy04](https://github.com/fryguy04): the multi-file JSON example
- [@alpiquero](https://github.com/alpiquero): the boolean parsing fix
- [@glorello](https://github.com/glorello): packaging and column alignment fixes

## License

Apache License 2.0. See [LICENSE.txt](LICENSE.txt).
