#!/usr/bin/env python3
"""Generate parsezeeklogs/_ecs_tables.py from the Elastic Common Schema and the
Filebeat Zeek module, both at pinned versions.

    uv run --with pyyaml scripts/build_ecs_tables.py

Sources (fetched from GitHub):
  * elastic/ecs   generated/ecs/ecs_flat.yml            -> ECS field types
  * elastic/beats x-pack/filebeat/module/zeek/<fileset>/ -> renames, copies, drops,
    event categorisation (config/<fileset>.yml) and zeek.* field types (_meta/fields.yml)

The output is a data-only module; the transform logic lives in parsezeeklogs/ecs.py.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
import urllib.request

import yaml

ECS_VERSION = "9.5.0"
BEATS_VERSION = "9.5.3"
ECS_URL = f"https://raw.githubusercontent.com/elastic/ecs/v{ECS_VERSION}/generated/ecs/ecs_flat.yml"
BEATS_URL = (
    f"https://raw.githubusercontent.com/elastic/beats/v{BEATS_VERSION}/x-pack/filebeat/module/zeek"
)
FILESETS = [
    "capture_loss",
    "connection",
    "dce_rpc",
    "dhcp",
    "dnp3",
    "dns",
    "dpd",
    "files",
    "ftp",
    "http",
    "intel",
    "irc",
    "kerberos",
    "modbus",
    "mysql",
    "notice",
    "ntlm",
    "ntp",
    "ocsp",
    "pe",
    "radius",
    "rdp",
    "rfb",
    "signature",
    "sip",
    "smb_cmd",
    "smb_files",
    "smb_mapping",
    "smtp",
    "snmp",
    "socks",
    "ssh",
    "ssl",
    "stats",
    "syslog",
    "traceroute",
    "tunnel",
    "weird",
    "x509",
]
#: ECS fields the hand-written logic in ecs.py sets that the module texts may not mention.
EXTRA_ECS_FIELDS = [
    "@timestamp",
    "ecs.version",
    "event.kind",
    "event.category",
    "event.type",
    "event.module",
    "event.dataset",
    "event.created",
    "event.id",
    "event.duration",
    "event.action",
    "event.outcome",
    "event.original",
    "tags",
    "related.ip",
    "related.user",
    "related.hash",
    "network.community_id",
    "network.direction",
    "network.bytes",
    "network.packets",
    "network.transport",
    "network.protocol",
    "network.name",
    "source.ip",
    "source.port",
    "source.address",
    "source.bytes",
    "source.packets",
    "source.mac",
    "destination.ip",
    "destination.port",
    "destination.address",
    "destination.bytes",
    "destination.packets",
    "destination.mac",
    "client.ip",
    "client.address",
    "server.ip",
    "server.address",
    "dns.id",
    "dns.type",
    "dns.question.name",
    "dns.question.type",
    "dns.question.class",
    "dns.response_code",
    "dns.header_flags",
    "dns.answers.data",
    "dns.answers.ttl",
    "dns.resolved_ip",
    "dns.op_code",
    "user.name",
    "user.domain",
    "rule.name",
    "rule.id",
    "rule.description",
    "file.name",
    "file.size",
    "file.mime_type",
    "file.path",
    "file.hash.md5",
    "file.hash.sha1",
    "file.hash.sha256",
    "file.accessed",
    "file.ctime",
    "file.created",
    "file.mtime",
    "tls.version",
    "tls.version_protocol",
    "tls.cipher",
    "tls.curve",
    "tls.established",
    "tls.resumed",
    "tls.client.server_name",
    "tls.client.ja3",
    "tls.server.ja3s",
    "tls.server.subject",
    "tls.server.issuer",
    "tls.client.subject",
    "tls.client.issuer",
    "tls.next_protocol",
    "http.request.method",
    "http.request.body.bytes",
    "http.request.referrer",
    "http.response.status_code",
    "http.response.body.bytes",
    "http.version",
    "url.original",
    "url.domain",
    "url.port",
    "url.username",
    "url.password",
    "url.full",
    "url.scheme",
    "user_agent.original",
    "log.syslog.facility.name",
    "log.syslog.severity.name",
]


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - pinned GitHub URLs
        return resp.read().decode("utf-8")


def fetch_optional(url: str) -> str:
    try:
        return fetch(url)
    except Exception:  # noqa: BLE001 - not every fileset has every file
        return ""


def parse_config(fs: str, text: str) -> dict:
    """Pull rename/copy/drop/event tables out of a Filebeat fileset config.

    The configs are Go templates; every line carrying a template expression is
    dropped so the rest parses as YAML.
    """
    ns = f"zeek.{fs}"

    def norm(name: str) -> str:
        name = str(name).strip()
        if name == "json":
            return ns
        if name.startswith("json."):
            return ns + name[4:]
        return name

    cleaned = "\n".join(line for line in text.splitlines() if "{{" not in line and "}}" not in line)
    doc = yaml.safe_load(cleaned) or {}
    renames: list[tuple[str, str]] = []
    copies: list[tuple[str, str, str]] = []
    drops: list[str] = []
    event: dict = {}
    network: dict = {}
    for proc in doc.get("processors") or []:
        if not isinstance(proc, dict) or len(proc) != 1:
            continue
        ((kind, body),) = proc.items()
        body = body or {}
        if kind == "rename":
            if any(k.startswith("when") for k in body):
                continue  # the ICMP special case is implemented in ecs.py
            for f in body.get("fields", []):
                src, dst = norm(f["from"]), norm(f["to"])
                if src in ("message", ns) and dst in ("event.original", ns):
                    continue
                renames.append((src, dst))
        elif kind == "convert":
            target = renames if body.get("mode") == "rename" else copies
            for f in body.get("fields", []):
                if "to" not in f:
                    continue  # in-place type conversion; handled by the type pass
                entry = (norm(f["from"]), norm(f["to"]))
                target.append(entry if target is renames else (*entry, str(f.get("type", ""))))
        elif kind == "drop_fields":
            drops += [norm(d) for d in body.get("fields", [])]
        elif kind == "add_fields":
            if body.get("target") == "event":
                event = body.get("fields", {})
            elif body.get("target") == "network":
                network = body.get("fields", {})
    return {
        "renames": renames,
        "copies": copies,
        "drops": drops,
        "event": event,
        "network": network,
    }


_TYPE_MAP = {
    "keyword": "keyword",
    "text": "text",
    "match_only_text": "match_only_text",
    "wildcard": "wildcard",
    "constant_keyword": "keyword",
    "long": "long",
    "integer": "integer",
    "short": "integer",
    "byte": "integer",
    "double": "double",
    "float": "float",
    "scaled_float": "double",
    "half_float": "float",
    "boolean": "boolean",
    "ip": "ip",
    "date": "date",
    "flattened": "flattened",
    "object": "object",
    "geo_point": "geo_point",
    "nested": "nested",
}


def walk_fields(nodes: list, prefix: str, out: dict[str, str]) -> None:
    for node in nodes or []:
        name = node.get("name")
        if not name:
            continue
        full = f"{prefix}.{name}" if prefix else name
        ntype = node.get("type", "group" if "fields" in node else "keyword")
        if ntype == "group":
            walk_fields(node.get("fields", []), full, out)
        elif ntype == "alias":
            continue
        elif ntype in _TYPE_MAP:
            out[full] = _TYPE_MAP[ntype]
            if "fields" in node:
                walk_fields(node["fields"], full, out)


def main() -> int:
    print(f"fetching ECS {ECS_VERSION} ...", file=sys.stderr)
    ecs = yaml.safe_load(fetch(ECS_URL))
    ecs_types: dict[str, str] = {}
    ecs_arrays: set[str] = set()
    for name, spec in ecs.items():
        ecs_types[name] = _TYPE_MAP.get(spec.get("type", "keyword"), "keyword")
        if spec.get("normalize"):
            ecs_arrays.add(name)

    print(f"fetching Filebeat zeek module {BEATS_VERSION} ...", file=sys.stderr)
    filesets: dict[str, dict] = {}
    zeek_types: dict[str, str] = {}
    meta = fetch_optional(f"{BEATS_URL}/_meta/fields.yml")
    for top in yaml.safe_load(meta) or []:
        walk_fields(top.get("fields", []), "", zeek_types)
    all_text = meta
    for fs in FILESETS:
        cfg = fetch_optional(f"{BEATS_URL}/{fs}/config/{fs}.yml")
        pipe = fetch_optional(f"{BEATS_URL}/{fs}/ingest/pipeline.yml")
        fields = fetch_optional(f"{BEATS_URL}/{fs}/_meta/fields.yml")
        all_text += cfg + pipe
        if cfg:
            filesets[fs] = parse_config(fs, cfg)
        for top in yaml.safe_load(fields) or []:
            walk_fields([top], "zeek", zeek_types)

    referenced = set(EXTRA_ECS_FIELDS)
    for token in set(re.findall(r"[a-z_@][a-z0-9_]*(?:\.[a-z0-9_]+)+", all_text)):
        if token in ecs_types:
            referenced.add(token)
    field_types = {k: ecs_types[k] for k in sorted(referenced) if k in ecs_types}
    field_types.update({k: v for k, v in sorted(zeek_types.items()) if k.startswith("zeek.")})
    arrays = sorted(a for a in ecs_arrays if a in field_types)

    out = pathlib.Path(__file__).resolve().parents[1] / "parsezeeklogs" / "_ecs_tables.py"
    with out.open("w", encoding="utf-8") as fh:
        fh.write('"""Generated by scripts/build_ecs_tables.py. Do not edit by hand.\n\n')
        fh.write(f"Elastic Common Schema {ECS_VERSION} field types plus the rename/copy/drop\n")
        fh.write(f"tables and zeek.* field types of the Filebeat {BEATS_VERSION} Zeek module.\n")
        fh.write('"""\n\n')
        fh.write(f"ECS_VERSION = {ECS_VERSION!r}\n")
        fh.write(f"BEATS_VERSION = {BEATS_VERSION!r}\n\n")
        fh.write("#: Elasticsearch field type per dotted field name (ECS fields used by the\n")
        fh.write("#: transform, and every zeek.* field the Filebeat module defines).\n")
        fh.write("FIELD_TYPES: dict[str, str] = " + json.dumps(field_types, indent=4) + "\n\n")
        fh.write("#: ECS fields whose value is always an array.\n")
        fh.write(
            "ARRAY_FIELDS: frozenset[str] = frozenset(" + json.dumps(arrays, indent=4) + ")\n\n"
        )
        fh.write("#: Per Filebeat fileset: sequential renames, copies (with optional type),\n")
        fh.write("#: dropped fields, and the constant event/network fields the module adds.\n")
        fh.write("FILESETS: dict[str, dict] = " + json.dumps(filesets, indent=4) + "\n")
    print(
        f"wrote {out} ({len(field_types)} field types, {len(filesets)} filesets)", file=sys.stderr
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
