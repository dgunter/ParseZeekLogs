"""Edge cases of the ECS helpers and per-log post-processors that the fixtures never hit."""

from datetime import datetime, timezone

import pytest

from parsezeeklogs import ecs
from parsezeeklogs.ecs import ecs_index_body, unflatten

NS = "zeek.x"


# -- coercion helpers ----------------------------------------------------------------------


def test_append_variants():
    flat = {}
    ecs._append(flat, "k", None)
    assert flat == {}
    ecs._append(flat, "k", "a")
    ecs._append(flat, "k", "a")  # scalar, same value: unchanged
    assert flat["k"] == ["a"]
    ecs._append(flat, "k", "b")
    ecs._append(flat, "k", "b")  # list, duplicate: unchanged
    assert flat["k"] == ["a", "b"]
    flat["s"] = "x"
    ecs._append(flat, "s", "x")
    assert flat["s"] == "x"
    ecs._append(flat, "s", "y")
    assert flat["s"] == ["x", "y"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, 1),
        (7, 7),
        (2.6, 3),
        ("0x1F", 31),
        (" 12 ", 12),
        ("3.7", 4),
        ("abc", None),
        (None, None),
        ([1], None),
    ],
)
def test_as_int(value, expected):
    assert ecs._as_int(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, 1.0), (2, 2.0), ("1.5", 1.5), ("x", None), (None, None)],
)
def test_as_float(value, expected):
    assert ecs._as_float(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (False, False),
        (0, False),
        (2.0, True),
        ("T", True),
        ("yes", True),
        ("F", False),
        ("no", False),
        ("maybe", None),
        (None, None),
    ],
)
def test_as_bool(value, expected):
    assert ecs._as_bool(value) is expected


def test_as_str_and_ip():
    assert ecs._as_str(True) == "true"
    assert ecs._as_str(False) == "false"
    stamp = datetime(2020, 9, 13, 12, 26, 40, tzinfo=timezone.utc)
    assert ecs._as_str(stamp) == "2020-09-13T12:26:40+00:00"
    assert ecs._as_str(5) == "5"
    assert ecs._as_ip(" 10.0.0.1 ") == "10.0.0.1"
    assert ecs._as_ip("not-an-ip") is None


def test_parse_dn_skips_unknown_and_malformed_parts():
    assert ecs._parse_dn("CN=a\\, b,X=1,junk,O=Org") == {
        "common_name": "a b",
        "organization": "Org",
    }


# -- post-processors -----------------------------------------------------------------------


def test_dns_edge_cases():
    flat = {f"{NS}.qclass": 0, f"{NS}.answers": ["a", "b"], f"{NS}.TTLs": [1.0]}
    ecs._post_dns(flat, NS)
    assert "dns.question.class" not in flat
    assert "dns.answers" not in flat  # answers and TTLs disagree in length
    flat = {f"{NS}.answers": ["cname.example"], f"{NS}.TTLs": [5.0]}
    ecs._post_dns(flat, NS)
    assert flat["dns.answers"] == [{"data": "cname.example", "ttl": 5}]
    assert "dns.resolved_ip" not in flat
    assert flat["dns.type"] == "query"


def test_http_without_action_or_status():
    flat = {}
    ecs._post_http(flat, NS)
    assert flat == {}
    flat = {"event.action": "GET", "http.response.status_code": "n/a"}
    ecs._post_http(flat, NS)
    assert flat["event.action"] == "get"
    assert "event.outcome" not in flat


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("SSLv3", ("3.0", "ssl")),
        ("TLSv12", ("1.2", "tls")),
        ("TLSv", None),
        ("v12", None),
        ("weird", None),
        (12, None),
    ],
)
def test_ssl_version_parsing(version, expected):
    flat = {f"{NS}.version": version}
    ecs._post_ssl(flat, NS)
    if expected is None:
        assert "tls.version" not in flat
    else:
        assert (flat["tls.version"], flat["tls.version_protocol"]) == expected


def test_kerberos_without_validity_or_result():
    flat = {f"{NS}.valid.from": 1.0}
    ecs._post_kerberos(flat, NS)
    assert f"{NS}.valid.days" not in flat
    assert "event.outcome" not in flat


def test_files_hosts_and_session_edge_cases():
    flat = {"event.id": "C1", f"{NS}.session_ids": [], f"{NS}.tx_hosts": "10.0.0.6"}
    ecs._post_files(flat, NS)
    assert "server.ip" not in flat
    flat = {"event.id": "C1", f"{NS}.session_ids": ["C9"], f"{NS}.rx_hosts": ["nope"]}
    ecs._post_files(flat, NS)
    assert flat["event.id"] == "C1"
    assert flat[f"{NS}.rx_host"] == "nope"
    assert "client.ip" not in flat
    assert "related.ip" not in flat


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("SMB::FILE_DELETE", "deletion"),
        ("SMB::FILE_RENAME", "change"),
        ("SMB::FILE_SET_ATTRIBUTE", "change"),
        ("SMB::FILE_OPEN", "info"),
        (None, None),
    ],
)
def test_smb_files_actions(action, expected):
    flat = {f"{NS}.path": "\\\\srv\\share"}  # path without a name: no file.path
    if action:
        flat[f"{NS}.action"] = action
    ecs._post_smb_files(flat, NS)
    assert "file.path" not in flat
    assert "file.accessed" not in flat
    assert flat.get("event.type", [None])[-1] == expected


def test_missing_or_odd_status_fields_are_ignored():
    for post in (ecs._post_smb_cmd, ecs._post_socks, ecs._post_sip, ecs._post_mysql, ecs._post_ssh):
        flat = {}
        post(flat, NS)
        assert flat == {}
    flat = {f"{NS}.status": 5, f"{NS}.status.code": "x", f"{NS}.cmd": 1}
    for post in (ecs._post_smb_cmd, ecs._post_sip, ecs._post_mysql):
        post(flat, NS)
    assert "event.outcome" not in flat
    assert "event.type" not in flat


def test_sip_success_and_mysql_connect_out():
    flat = {f"{NS}.status.code": 200}
    ecs._post_sip(flat, NS)
    assert flat["event.outcome"] == "success"
    assert "event.type" not in flat
    flat = {f"{NS}.cmd": "connect_out"}
    ecs._post_mysql(flat, NS)
    assert flat["event.type"] == ["access", "end"]


def test_x509_without_algorithm_or_validity():
    flat = {f"{NS}.certificate.signature_algorithm": None, f"{NS}.certificate.valid.from": None}
    ecs._post_x509(flat, NS)
    assert "file.x509.signature_algorithm" not in flat
    assert "file.x509.not_before" not in flat


def test_common_post_skips_community_id_it_cannot_compute():
    flat = {"source.ip": "10.0.0.1", "destination.ip": "10.0.0.2", "network.transport": "bogus"}
    ecs._common_post(flat)
    assert "network.community_id" not in flat
    assert flat["event.category"] == ["network"]


def test_add_constants_applies_network_defaults():
    flat = {"network.protocol": "dns"}
    spec = {"event": {"type": ["info"]}, "network": {"protocol": "http", "transport": "udp"}}
    ecs._add_constants(flat, None, "dns", spec)
    assert flat["network.protocol"] == "dns"  # existing value wins
    assert flat["network.transport"] == "udp"
    assert "@timestamp" not in flat
    assert flat["event.kind"] == "event"


# -- coercion of arrays, unflatten, mapping -------------------------------------------------


def test_empty_array_field_is_dropped():
    assert ecs._coerce_value("dns.answers", []) is None
    assert ecs._coerce_value("dns.answers", "a") == ["a"]


def test_unflatten_dict_values_and_conflicts():
    doc = unflatten({"a": {"x": 1}, "a.b": 2, "c.d": 3, "c": 4})
    assert doc == {"a": {"x": 1, "b": 2}, "c": {"value": 4, "d": 3}}


def test_index_body_handles_every_field_shape(monkeypatch):
    monkeypatch.setattr(
        ecs,
        "FIELD_TYPES",
        {
            "a": "keyword",  # a scalar that is also a parent: the object wins
            "a.b": "long",
            "f": "flattened",
            "f.x": "keyword",  # children of a flattened field are not mapped
            "n": "nested",
            "n.y": "ip",
            "o.p": "keyword",
        },
    )
    props = ecs_index_body()["mappings"]["properties"]
    assert props["a"] == {"type": "object", "properties": {"b": {"type": "long"}}}
    assert props["f"] == {"type": "flattened"}
    assert props["n"] == {"type": "nested", "properties": {"y": {"type": "ip"}}}
    assert props["o"] == {"type": "object", "properties": {"p": {"type": "keyword"}}}
    assert props["@timestamp"] == {"type": "date"}
