# Test fixtures

| Path | What | Origin |
| --- | --- | --- |
| `conn_2018.log` | TSV `conn.log`, 2,164 records, written by a Zeek 2.5-era `LogAscii` | the sample that shipped with ParseZeekLogs 1.x/2.x (`examples/conn.log`) |
| `rdp_sharprdp/{tsv,json}/*.log` | every log Zeek 8.2.2 produced for one capture, in both output formats | [PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK) `Lateral Movement/LM_rdp_sharprdp.pcapng`, via `scripts/generate_zeek_logs.sh` |
| `c2_dns_txt/{tsv,json}/dns.log` | a `dns.log` with `vector[string]` / `vector[interval]` answers | PCAP-ATTACK `Command and Control/cmds over dns txt queries and reponses.pcapng` |

`loaded_scripts.log` is omitted from `rdp_sharprdp` (38 KB of script paths, no
parsing value). Zeek was run with `-D` (deterministic seeds) so the TSV and
JSON renderings of a capture carry identical UIDs and can be compared record
for record. The full generated corpus for every capture is produced by
`scripts/generate_zeek_logs.sh` into `.cache/zeek-logs/` and exercised by
`pytest -m samples`.
