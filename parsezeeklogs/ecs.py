"""Map Zeek records to Elastic Common Schema (ECS) documents.

The layout follows the Filebeat Zeek module: common fields become ECS
(``source.ip``, ``destination.port``, ``network.transport``, ``event.*``,
``dns.*``, ``tls.*``, ``file.*`` ...), everything else lands under
``zeek.<fileset>.*``, and ``zeek.session_id`` / ``event.id`` carry the Zeek
``uid``. The rename, copy and drop tables and the field types come from
:mod:`parsezeeklogs._ecs_tables`, generated from ECS |ECS_VERSION| and the
Filebeat |BEATS_VERSION| module by ``scripts/build_ecs_tables.py``; the
per-log logic of the module's ingest pipelines is reimplemented below.

Every emitted value is coerced to the ECS/Beats field type (``long`` -> int,
``boolean`` -> bool, ``ip`` -> validated address string, ``date`` -> ISO-8601,
array fields -> lists), and :func:`ecs_index_body` produces an Elasticsearch
mapping from the same table so documents and index agree.

Not reproduced: GeoIP/ASN enrichment, user-agent parsing and public-suffix
based ``dns.question.registered_domain`` (those need external databases).
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
import struct
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any

from parsezeeklogs._ecs_tables import (
    ARRAY_FIELDS,
    BEATS_VERSION,
    ECS_VERSION,
    FIELD_TYPES,
    FILESETS,
)

__all__ = [
    "BEATS_VERSION",
    "ECS_VERSION",
    "community_id",
    "ecs_index_body",
    "to_ecs",
    "unflatten",
]

log = logging.getLogger(__name__)

#: Zeek log paths whose Filebeat fileset has a different name.
PATH_TO_FILESET = {"conn": "connection"}

# ECS field names used throughout.
EVENT_TYPE = "event.type"
EVENT_OUTCOME = "event.outcome"
EVENT_ACTION = "event.action"
EVENT_ID = "event.id"
SESSION_ID = "zeek.session_id"
SOURCE_IP = "source.ip"
SOURCE_PORT = "source.port"
DESTINATION_IP = "destination.ip"
DESTINATION_PORT = "destination.port"
NETWORK_TRANSPORT = "network.transport"

Flat = dict[str, Any]


# -- small helpers ----------------------------------------------------------------------


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    if isinstance(value, str) and value:
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
        except ValueError:
            return value  # already a textual timestamp
    return None


def _move(flat: Flat, src: str, dst: str) -> None:
    """Rename ``src`` to ``dst`` unless ``dst`` exists (Filebeat's ``fail_on_error: false``)."""
    if src in flat and dst not in flat:
        flat[dst] = flat.pop(src)


def _copy(flat: Flat, src: str, dst: str, typ: str = "") -> None:
    if src not in flat or dst in flat:
        return
    value = flat[src]
    if typ == "ip":
        value = _as_ip(value)
    elif typ == "long":
        value = _as_int(value)
    elif typ == "string":
        value = str(value)
    elif typ == "boolean":
        value = _as_bool(value)
    if value is not None:
        flat[dst] = value


def _append(flat: Flat, key: str, value: Any) -> None:
    if value is None:
        return
    current = flat.get(key)
    if current is None:
        flat[key] = [value]
    elif isinstance(current, list):
        if value not in current:
            current.append(value)
    elif current != value:
        flat[key] = [current, value]


def _as_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(round(value))
    if isinstance(value, str):
        try:
            return int(value.strip(), 0) if value.strip().lower().startswith("0x") else int(value)
        except ValueError:
            try:
                return int(round(float(value)))
            except ValueError:
                return None
    return None


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("t", "true", "1", "yes"):
            return True
        if text in ("f", "false", "0", "no"):
            return False
    return None


def _as_str(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


_DN_KEYS = {
    "C": "country",
    "CN": "common_name",
    "L": "locality",
    "O": "organization",
    "OU": "organizational_unit",
    "ST": "state_or_province",
}


def _parse_dn(text: str) -> dict[str, str]:
    """``CN=foo,O=bar,C=US`` -> ``{"common_name": "foo", ...}``; escaped commas are dropped."""
    out: dict[str, str] = {}
    for part in text.replace("\\,", "").split(","):
        key, sep, value = part.partition("=")
        if sep and key.strip() in _DN_KEYS:
            out[_DN_KEYS[key.strip()]] = value.strip()
    return out


# -- Community ID -----------------------------------------------------------------------

_PROTO_NUMBERS = {"tcp": 6, "udp": 17, "sctp": 132, "icmp": 1, "icmp6": 58, "icmpv6": 58}
_ICMP4_PAIRS = {8: 0, 0: 8, 13: 14, 14: 13, 15: 16, 16: 15, 10: 9, 9: 10, 17: 18, 18: 17}
_ICMP6_PAIRS = {
    128: 129, 129: 128, 133: 134, 134: 133, 135: 136, 136: 135,
    130: 131, 131: 130, 139: 140, 140: 139, 144: 145, 145: 144,
}  # fmt: skip


def _protocol_number(proto: str | int, ip_version: int) -> int | None:
    if isinstance(proto, int):
        return proto
    name = proto.lower()
    if name == "icmp" and ip_version == 6:
        name = "icmp6"
    return _PROTO_NUMBERS.get(name)


def _flow_ports(
    number: int, sport: int | None, dport: int | None
) -> tuple[int | None, int | None, bool] | None:
    """Return (sport, dport, one_way) for the hash, or None when the flow has no valid ports."""
    if number in (1, 58):
        pairs = _ICMP4_PAIRS if number == 1 else _ICMP6_PAIRS
        icmp_type = sport if sport is not None else 0
        if icmp_type in pairs:
            return icmp_type, pairs[icmp_type], False
        return icmp_type, dport if dport is not None else 0, True
    if number in (6, 17, 132):
        if sport is None or dport is None:
            return None
        return sport, dport, False
    return None, None, False


def community_id(
    saddr: str,
    daddr: str,
    proto: str | int,
    sport: int | None = None,
    dport: int | None = None,
    seed: int = 0,
) -> str | None:
    """Community ID v1 flow hash (https://github.com/corelight/community-id-spec).

    For ICMP, ``sport``/``dport`` are the ICMP type and code, as Zeek logs them.
    Returns ``None`` when the addresses or protocol cannot be interpreted.
    """
    try:
        src = ipaddress.ip_address(saddr)
        dst = ipaddress.ip_address(daddr)
    except ValueError:
        return None
    if src.version != dst.version:
        return None
    number = _protocol_number(proto, src.version)
    if number is None:
        return None
    ports = _flow_ports(number, sport, dport)
    if ports is None:
        return None
    sport, dport, one_way = ports

    if not one_way and (dst.packed < src.packed or (src == dst and (dport or 0) < (sport or 0))):
        src, dst = dst, src
        sport, dport = dport, sport

    data = struct.pack("!H", seed) + src.packed + dst.packed + struct.pack("!BB", number, 0)
    if sport is not None and dport is not None:
        data += struct.pack("!HH", sport & 0xFFFF, dport & 0xFFFF)
    # SHA-1 is what the Community ID specification mandates; this is a flow
    # identifier, not a security control.
    digest = hashlib.sha1(data).digest()  # NOSONAR python:S4790  # noqa: S324
    return "1:" + base64.b64encode(digest).decode("ascii")


# -- per-fileset logic (the ingest pipelines) --------------------------------------------

_CONN_STATES: dict[str, tuple[str, list[str]]] = {
    "S0": ("Connection attempt seen, no reply.", ["connection", "start"]),
    "S1": ("Connection established, not terminated.", ["connection", "start"]),
    "SF": ("Normal establishment and termination.", ["connection", "start", "end"]),
    "REJ": ("Connection attempt rejected.", ["connection", "start", "denied"]),
    "S2": (
        "Connection established and close attempt by originator seen "
        "(but no reply from responder).",
        ["connection", "info"],
    ),
    "S3": (
        "Connection established and close attempt by responder seen "
        "(but no reply from originator).",
        ["connection", "info"],
    ),
    "RSTO": ("Connection established, originator aborted (sent a RST).", ["connection", "info"]),
    "RSTR": ("Responder sent a RST.", ["connection", "info"]),
    "RSTOS0": (
        "Originator sent a SYN followed by a RST, we never saw a SYN-ACK from the responder.",
        ["connection", "info"],
    ),
    "RSTRH": (
        "Responder sent a SYN ACK followed by a RST, we never saw a SYN from the "
        "(purported) originator.",
        ["connection", "info"],
    ),
    "SH": (
        "Originator sent a SYN followed by a FIN, we never saw a SYN ACK from the responder "
        "(hence the connection was 'half' open).",
        ["connection", "info"],
    ),
    "SHR": (
        "Responder sent a SYN ACK followed by a FIN, we never saw a SYN from the originator.",
        ["connection", "info"],
    ),
    "OTH": (
        "No SYN seen, just midstream traffic (a 'partial connection' that was not later closed).",
        ["connection", "info"],
    ),
}


def _post_connection(flat: Flat, ns: str) -> None:
    duration = flat.pop("temp.duration", None)
    if duration is not None:
        flat["event.duration"] = int(round(float(duration) * 1_000_000_000))
    local_orig, local_resp = flat.get(f"{ns}.local_orig"), flat.get(f"{ns}.local_resp")
    if local_orig:
        _append(flat, "tags", "local_orig")
    if local_resp:
        _append(flat, "tags", "local_resp")
    for total, parts in (
        ("network.packets", ("source.packets", "destination.packets")),
        ("network.bytes", ("source.bytes", "destination.bytes")),
    ):
        values = [_as_int(flat.get(key)) for key in parts]
        if None not in values:
            flat[total] = sum(values)  # type: ignore[arg-type]
    if local_orig is not None and local_resp is not None:
        flat["network.direction"] = {
            (True, True): "internal",
            (True, False): "outbound",
            (False, True): "inbound",
            (False, False): "external",
        }[(bool(local_orig), bool(local_resp))]
    state = flat.get(f"{ns}.state")
    if state in _CONN_STATES:
        message, types = _CONN_STATES[state]
        flat[f"{ns}.state_message"] = message
        flat[EVENT_TYPE] = list(types)


_DNS_CLASSES = {1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}


def _post_dns(flat: Flat, ns: str) -> None:
    for flag in ("AA", "TC", "RD", "RA"):
        if flat.get(f"{ns}.{flag}") is True:
            _append(flat, "dns.header_flags", flag)
    qclass = flat.get(f"{ns}.qclass")
    if qclass:
        flat["dns.question.class"] = _DNS_CLASSES.get(qclass, str(qclass))
    answers, ttls = flat.get(f"{ns}.answers"), flat.get(f"{ns}.TTLs")
    if isinstance(answers, list) and isinstance(ttls, list) and len(answers) == len(ttls):
        flat["dns.answers"] = [
            {"data": a, "ttl": _as_int(t)} for a, t in zip(answers, ttls, strict=True)
        ]
        resolved = [a for a in answers if _as_ip(a)]
        if resolved:
            flat["dns.resolved_ip"] = resolved
    flat["dns.type"] = "answer" if flat.get(f"{ns}.rcode_name") else "query"
    rtt = flat.get(f"{ns}.rtt")
    if rtt:
        flat["event.duration"] = int(round(float(rtt) * 1_000_000_000))
    rcode = flat.get(f"{ns}.rcode")
    if rcode is not None:
        flat[EVENT_OUTCOME] = "success" if rcode == 0 else "failure"


def _post_http(flat: Flat, ns: str) -> None:
    if isinstance(flat.get(EVENT_ACTION), str):
        flat[EVENT_ACTION] = flat[EVENT_ACTION].lower()
    status = flat.get("http.response.status_code")
    if isinstance(status, int):
        flat[EVENT_OUTCOME] = "success" if status < 400 else "failure"


def _x509_subjects(flat: Flat, pairs: Iterable[tuple[str, str, str]]) -> None:
    """Explode DN strings: (source key, zeek object prefix, ecs prefix)."""
    for src, zeek_prefix, ecs_prefix in pairs:
        text = flat.get(src)
        if not isinstance(text, str):
            continue
        for name, value in _parse_dn(text).items():
            flat[f"{zeek_prefix}.{name}"] = value
            flat[f"{ecs_prefix}.{name}"] = value


def _post_ssl(flat: Flat, ns: str) -> None:
    _x509_subjects(
        flat,
        [
            (f"{ns}.issuer", f"{ns}.server.issuer", "tls.server.x509.issuer"),
            (f"{ns}.subject", f"{ns}.server.subject", "tls.server.x509.subject"),
            (f"{ns}.client_issuer", f"{ns}.client.issuer", "tls.client.x509.issuer"),
            (f"{ns}.client_subject", f"{ns}.client.subject", "tls.client.x509.subject"),
        ],
    )
    _move(flat, f"{ns}.issuer", "tls.server.issuer")
    _move(flat, f"{ns}.subject", "tls.server.subject")
    _move(flat, f"{ns}.client_issuer", "tls.client.issuer")
    _move(flat, f"{ns}.client_subject", "tls.client.subject")
    _copy(flat, f"{ns}.cipher", "tls.cipher")
    _copy(flat, f"{ns}.curve", "tls.curve")
    _copy(flat, f"{ns}.established", "tls.established", "boolean")
    _copy(flat, f"{ns}.resumed", "tls.resumed", "boolean")
    _copy(flat, f"{ns}.server.name", "tls.client.server_name")
    _copy(flat, f"{ns}.next_protocol", "tls.next_protocol")
    version = flat.get(f"{ns}.version")
    if isinstance(version, str) and version.count("v") == 1:
        proto, number = version.split("v")
        if proto and number:
            flat["tls.version"] = f"{number}.0" if proto == "SSL" else f"{number[0]}.{number[1:]}"
            flat["tls.version_protocol"] = proto.lower()


def _post_kerberos(flat: Flat, ns: str) -> None:
    # Zeek writes client_cert_subject etc.; the Filebeat config expects cert.client_subject.
    for side in ("client", "server"):
        _move(flat, f"{ns}.{side}_cert", f"{ns}.cert.{side}.value")
        _move(flat, f"{ns}.{side}_cert_subject", f"{ns}.cert.{side}.subject")
        _move(flat, f"{ns}.{side}_cert_fuid", f"{ns}.cert.{side}.fuid")
    valid_from, valid_until = flat.get(f"{ns}.valid.from"), flat.get(f"{ns}.valid.until")
    if isinstance(valid_from, (int, float)) and isinstance(valid_until, (int, float)):
        flat[f"{ns}.valid.days"] = int(round((valid_until - valid_from) / 86400))
    success = flat.get(f"{ns}.success")
    if success is True:
        flat[EVENT_OUTCOME] = "success"
    elif success is False:
        flat[EVENT_OUTCOME] = "failure"
    _x509_subjects(
        flat,
        [
            (
                f"{ns}.cert.client.subject",
                f"{ns}.cert.client.subject_dn",
                "tls.client.x509.subject",
            ),
            (
                f"{ns}.cert.server.subject",
                f"{ns}.cert.server.subject_dn",
                "tls.server.x509.subject",
            ),
        ],
    )


def _post_files(flat: Flat, ns: str) -> None:
    session_ids = flat.get(f"{ns}.session_ids")
    if isinstance(session_ids, list) and session_ids and SESSION_ID not in flat:
        flat[SESSION_ID] = session_ids[0]
    for hosts_key, single_key, ecs_key in (
        (f"{ns}.tx_hosts", f"{ns}.tx_host", "server.ip"),
        (f"{ns}.rx_hosts", f"{ns}.rx_host", "client.ip"),
    ):
        hosts = flat.pop(hosts_key, None)
        if isinstance(hosts, list) and hosts:
            for host in hosts:
                _append(flat, "related.ip", _as_ip(host))
            flat[single_key] = hosts[0]
            ip = _as_ip(hosts[0])
            if ip:
                flat[ecs_key] = ip
    for algo in ("md5", "sha1", "sha256"):
        _append(flat, "related.hash", flat.get(f"file.hash.{algo}"))


def _post_smb_files(flat: Flat, ns: str) -> None:
    for zeek_key, ecs_key in (
        ("times.accessed", "file.accessed"),
        ("times.changed", "file.ctime"),
        ("times.created", "file.created"),
        ("times.modified", "file.mtime"),
    ):
        stamp = _iso(flat.get(f"{ns}.{zeek_key}"))
        if stamp:
            flat[ecs_key] = stamp
    path, name = flat.get(f"{ns}.path"), flat.get(f"{ns}.name")
    if path and name:
        flat["file.path"] = f"{path}\\{name}"
    action = flat.get(f"{ns}.action")
    if action == "SMB::FILE_DELETE":
        _append(flat, EVENT_TYPE, "deletion")
    elif action in ("SMB::FILE_RENAME", "SMB::FILE_SET_ATTRIBUTE"):
        _append(flat, EVENT_TYPE, "change")
    elif action:
        _append(flat, EVENT_TYPE, "info")


def _post_smb_cmd(flat: Flat, ns: str) -> None:
    status = flat.get(f"{ns}.status")
    if isinstance(status, str):
        if status.lower() == "success":
            flat[EVENT_OUTCOME] = "success"
        else:
            _append(flat, EVENT_TYPE, "error")


def _post_socks(flat: Flat, ns: str) -> None:
    status = flat.get(f"{ns}.status")
    if status is not None:
        if status == "succeeded":
            flat[EVENT_OUTCOME] = "success"
        else:
            _append(flat, EVENT_TYPE, "error")


def _post_sip(flat: Flat, ns: str) -> None:
    code = flat.get(f"{ns}.status.code")
    if isinstance(code, int):
        flat[EVENT_OUTCOME] = "success" if code < 400 else "failure"
        if code >= 400:
            _append(flat, EVENT_TYPE, "error")


_MYSQL_CHANGE = {"init_db", "change_user", "set_option", "drop_db", "create_db", "refresh"}


def _post_mysql(flat: Flat, ns: str) -> None:
    cmd = flat.get(f"{ns}.cmd")
    if not isinstance(cmd, str):
        return
    if cmd in ("connect", "connect_out"):
        _append(flat, EVENT_TYPE, "access")
    if cmd in _MYSQL_CHANGE:
        _append(flat, EVENT_TYPE, "change")
    elif cmd not in ("connect", "connect_out"):
        _append(flat, EVENT_TYPE, "info")
    if cmd == "connect":
        _append(flat, EVENT_TYPE, "start")
    if cmd == "connect_out":
        _append(flat, EVENT_TYPE, "end")


def _post_ssh(flat: Flat, ns: str) -> None:
    success = flat.get(f"{ns}.auth.success")
    if success is False:
        flat[EVENT_OUTCOME] = "failure"
    elif success is True:
        flat[EVENT_OUTCOME] = "success"


def _post_rdp(flat: Flat, ns: str) -> None:
    _copy(flat, f"{ns}.ssl", "tls.established", "boolean")


def _post_notice(flat: Flat, ns: str) -> None:
    if flat.get(f"{ns}.dropped") is False:
        _append(flat, EVENT_TYPE, "allowed")


_SIGNATURE_ALGORITHMS = {
    "md2WithRSAEncryption": "MD2-RSA",
    "md5WithRSAEncryption": "MD5-RSA",
    "sha-1WithRSAEncryption": "SHA1-RSA",
    "sha1WithRSAEncryption": "SHA1-RSA",
    "sha256WithRSAEncryption": "SHA256-RSA",
    "sha384WithRSAEncryption": "SHA384-RSA",
    "sha512WithRSAEncryption": "SHA512-RSA",
    "dsaWithSha1": "DSA-SHA1",
    "dsaWithSha256": "DSA-SHA256",
    "ecdsa-with-SHA1": "ECDSA-SHA1",
    "ecdsa-with-SHA256": "ECDSA-SHA256",
    "ecdsa-with-SHA384": "ECDSA-SHA384",
    "ecdsa-with-SHA512": "ECDSA-SHA512",
    "id-Ed25519": "Ed25519",
}


def _post_x509(flat: Flat, ns: str) -> None:
    cert = f"{ns}.certificate"
    algo = flat.get(f"{cert}.signature_algorithm")
    if isinstance(algo, str):
        flat["file.x509.signature_algorithm"] = _SIGNATURE_ALGORITHMS.get(algo, algo)
    _copy(flat, f"{cert}.key.algorithm", "file.x509.public_key_algorithm")
    _copy(flat, f"{cert}.key.length", "file.x509.public_key_size", "long")
    _copy(flat, f"{cert}.exponent", "file.x509.public_key_exponent", "long")
    _copy(flat, f"{cert}.serial", "file.x509.serial_number", "string")
    _copy(flat, f"{cert}.version", "file.x509.version_number", "string")
    for san in ("dns", "uri", "email", "ip", "other_fields"):
        values = flat.get(f"{ns}.san.{san}")
        if isinstance(values, list):
            for value in values:
                _append(flat, "file.x509.alternative_names", value)
    for zeek_key, ecs_key in (
        ("valid.from", "file.x509.not_before"),
        ("valid.until", "file.x509.not_after"),
    ):
        stamp = _iso(flat.get(f"{cert}.{zeek_key}"))
        if stamp:
            flat[f"{cert}.{zeek_key}"] = stamp
            flat[ecs_key] = stamp
    _x509_subjects(
        flat,
        [
            (f"{cert}.iss", f"{cert}.issuer", "file.x509.issuer"),
            (f"{cert}.sub", f"{cert}.subject", "file.x509.subject"),
        ],
    )
    flat.pop(f"{cert}.iss", None)
    flat.pop(f"{cert}.sub", None)


def _post_metric(flat: Flat, ns: str) -> None:
    flat["event.kind"] = "metric"
    flat.setdefault(EVENT_TYPE, ["info"])


_POST: dict[str, Callable[[Flat, str], None]] = {
    "connection": _post_connection,
    "dns": _post_dns,
    "http": _post_http,
    "ssl": _post_ssl,
    "kerberos": _post_kerberos,
    "files": _post_files,
    "smb_files": _post_smb_files,
    "smb_cmd": _post_smb_cmd,
    "socks": _post_socks,
    "sip": _post_sip,
    "mysql": _post_mysql,
    "ssh": _post_ssh,
    "rdp": _post_rdp,
    "notice": _post_notice,
    "x509": _post_x509,
    "capture_loss": _post_metric,
    "stats": _post_metric,
}


def _generic_spec(ns: str) -> dict[str, Any]:
    """Filebeat has no fileset for this log: map the connection 4-tuple and uid only."""
    return {
        "renames": [
            (f"{ns}.id.orig_h", "source.address"),
            (f"{ns}.id.orig_p", SOURCE_PORT),
            (f"{ns}.id.resp_h", "destination.address"),
            (f"{ns}.id.resp_p", DESTINATION_PORT),
            (f"{ns}.uid", SESSION_ID),
            (f"{ns}.proto", NETWORK_TRANSPORT),
        ],
        "copies": [
            (SESSION_ID, EVENT_ID, ""),
            ("source.address", SOURCE_IP, "ip"),
            ("destination.address", DESTINATION_IP, "ip"),
        ],
        "drops": [],
        "event": {"kind": "event", "type": ["info"]},
        "network": {},
    }


def _common_post(flat: Flat) -> None:
    for key in (SOURCE_IP, DESTINATION_IP):
        _append(flat, "related.ip", flat.get(key))
    _append(flat, "related.user", flat.get("user.name"))
    if EVENT_ID not in flat and SESSION_ID in flat:
        flat[EVENT_ID] = flat[SESSION_ID]
    src, dst, proto = (
        flat.get(SOURCE_IP),
        flat.get(DESTINATION_IP),
        flat.get(NETWORK_TRANSPORT),
    )
    if src and dst and proto and "network.community_id" not in flat:
        if proto == "icmp":
            sport = flat.get("zeek.connection.icmp.type", flat.get(SOURCE_PORT))
            dport = flat.get("zeek.connection.icmp.code", flat.get(DESTINATION_PORT))
        else:
            sport, dport = flat.get(SOURCE_PORT), flat.get(DESTINATION_PORT)
        cid = community_id(src, dst, proto, _as_int(sport), _as_int(dport))
        if cid:
            flat["network.community_id"] = cid
    if SOURCE_IP in flat and "event.category" not in flat:
        flat["event.category"] = ["network"]


# -- type coercion and nesting ------------------------------------------------------------

_COERCE: dict[str, Callable[[Any], Any]] = {
    "long": _as_int,
    "integer": _as_int,
    "double": _as_float,
    "float": _as_float,
    "boolean": _as_bool,
    "ip": _as_ip,
    "date": _iso,
    "keyword": _as_str,
    "text": _as_str,
    "wildcard": _as_str,
    "match_only_text": _as_str,
}


def _has_objects(value: Any) -> bool:
    return isinstance(value, dict) or (
        isinstance(value, list) and bool(value) and isinstance(value[0], dict)
    )


def _coerce_value(key: str, value: Any) -> Any:
    """Coerce one value to its ECS/Beats type; None means "drop the field"."""
    convert = _COERCE.get(FIELD_TYPES.get(key, ""))
    if convert is not None and not _has_objects(value):
        if isinstance(value, list):
            value = [c for c in (convert(v) for v in value) if c is not None]
        else:
            value = convert(value)
    if key in ARRAY_FIELDS:
        if value is not None and not isinstance(value, list):
            value = [value]
        if not value:
            return None
    return value


def _coerce_types(flat: Flat) -> None:
    coerced = {key: _coerce_value(key, value) for key, value in flat.items()}
    flat.clear()
    flat.update({key: value for key, value in coerced.items() if value is not None})


def unflatten(flat: Flat) -> dict[str, Any]:
    """``{"a.b": 1, "a.c": 2}`` -> ``{"a": {"b": 1, "c": 2}}``.

    When a key is both a value and a prefix of other keys the object wins and the
    scalar is kept under ``<key>.value``.
    """
    out: dict[str, Any] = {}
    for key in sorted(flat, key=lambda k: (k.count("."), k)):
        parts = key.split(".")
        node = out
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child_obj: dict[str, Any] = {} if child is None else {"value": child}
                node[part] = child_obj
                child = child_obj
            node = child
        # Keys are visited shortest first, so a leaf can never already be an object here.
        node[parts[-1]] = flat[key]
    return out


# -- public API -------------------------------------------------------------------------


def _seed_flat(record: dict[str, Any], ns: str, fileset: str, spec: dict[str, Any]) -> Flat:
    """Apply the module's drop/rename/copy tables to the raw record."""
    flat: Flat = {
        f"{ns}.{key}": value for key, value in record.items() if key != "ts" and value is not None
    }
    for key in spec["drops"]:
        flat.pop(key, None)
    for src, dst in spec["renames"]:
        _move(flat, src, dst)
    if fileset == "connection" and flat.get(NETWORK_TRANSPORT) == "icmp":
        _move(flat, SOURCE_PORT, f"{ns}.icmp.type")
        _move(flat, DESTINATION_PORT, f"{ns}.icmp.code")
    for src, dst, typ in spec["copies"]:
        _copy(flat, src, dst, typ)
    return flat


def _add_constants(flat: Flat, ts: Any, fileset: str, spec: dict[str, Any]) -> None:
    stamp = _iso(ts)
    if stamp:
        flat["@timestamp"] = stamp
        flat["event.created"] = stamp
    flat["event.module"] = "zeek"
    flat["event.dataset"] = f"zeek.{fileset}"
    for key, value in spec.get("event", {}).items():
        flat[f"event.{key}"] = list(value) if isinstance(value, list) else value
    for key, value in spec.get("network", {}).items():
        flat.setdefault(f"network.{key}", value)
    flat.setdefault("event.kind", "event")


def to_ecs(
    record: dict[str, Any], path: str | None, meta: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Return the ECS document for one Zeek ``record`` from log ``path`` (``conn``, ``dns`` ...)."""
    fileset = PATH_TO_FILESET.get(path or "", path or "unknown")
    ns = f"zeek.{fileset}"
    spec = FILESETS.get(fileset) or _generic_spec(ns)
    flat = _seed_flat(record, ns, fileset, spec)
    _add_constants(flat, record.get("ts"), fileset, spec)
    _POST.get(fileset, lambda _f, _n: None)(flat, ns)
    _common_post(flat)
    flat["ecs.version"] = ECS_VERSION
    if meta:
        flat.update(meta)
    _coerce_types(flat)
    return unflatten(flat)


_CONTAINER_TYPES = {"object", "nested", "flattened"}


def _mapping_parent(root: dict[str, Any], parts: list[str]) -> dict[str, Any] | None:
    """The ``properties`` dict that holds ``parts``; None when an ancestor is flattened."""
    node = root
    for part in parts:
        node = node.setdefault(part, {"type": "object", "properties": {}})
        if node.get("type") == "flattened":
            return None
        node = node.setdefault("properties", {})
    return node


def ecs_index_body() -> dict[str, Any]:
    """Elasticsearch index body whose mapping mirrors :data:`FIELD_TYPES`."""
    types = dict(FIELD_TYPES)
    types.setdefault("@timestamp", "date")
    types.setdefault("tags", "keyword")
    prefixes = {k.rsplit(".", 1)[0] for k in types if "." in k}
    root: dict[str, Any] = {}
    for key in sorted(types, key=lambda k: (k.count("."), k)):
        ftype = types[key]
        parts = key.split(".")
        node = _mapping_parent(root, parts[:-1])
        if node is None:
            continue  # children of a flattened field are not mapped
        leaf = parts[-1]
        if key in prefixes and ftype not in _CONTAINER_TYPES:
            # A scalar that is also a parent: Elasticsearch cannot map both, keep the object.
            node.setdefault(leaf, {"type": "object", "properties": {}})
            continue
        if ftype == "flattened":
            node[leaf] = {"type": "flattened"}
        elif ftype in _CONTAINER_TYPES:
            node.setdefault(leaf, {"type": ftype, "properties": {}})
        else:
            node[leaf] = {"type": ftype}
    return {
        "mappings": {
            "dynamic": True,
            "date_detection": False,
            "numeric_detection": False,
            "properties": root,
        }
    }
