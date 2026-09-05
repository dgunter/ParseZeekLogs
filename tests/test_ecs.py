import json
from datetime import datetime, timezone

import pytest

from parsezeeklogs import read_zeek
from parsezeeklogs._ecs_tables import ARRAY_FIELDS, FIELD_TYPES
from parsezeeklogs.ecs import ECS_VERSION, community_id, ecs_index_body, to_ecs, unflatten

TS = 1600000000.5
ISO = "2020-09-13T12:26:40.500000+00:00"
CONN = {
    "ts": TS,
    "uid": "CabcDEF123",
    "id.orig_h": "10.0.0.5",
    "id.orig_p": 51234,
    "id.resp_h": "93.184.216.34",
    "id.resp_p": 443,
    "proto": "tcp",
    "service": "ssl",
    "duration": 1.25,
    "orig_bytes": 100,
    "resp_bytes": 2000,
    "conn_state": "SF",
    "local_orig": True,
    "local_resp": False,
    "missed_bytes": 0,
    "history": "ShADadFf",
    "orig_pkts": 10,
    "orig_ip_bytes": 620,
    "resp_pkts": 12,
    "resp_ip_bytes": 2640,
    "tunnel_parents": [],
    "ip_proto": 6,
}


def flat(doc, prefix=""):
    """Flatten a nested doc back to dotted keys for easy assertions."""
    out = {}
    for k, v in doc.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flat(v, key + "."))
        else:
            out[key] = v
    return out


# -- community id ----------------------------------------------------------------------


def test_community_id_known_vector():
    # From the Community ID spec test data (tcp, 128.232.110.120:34855 -> 66.35.250.204:80)
    assert (
        community_id("128.232.110.120", "66.35.250.204", "tcp", 34855, 80)
        == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    )
    # Direction-independent
    assert (
        community_id("66.35.250.204", "128.232.110.120", "tcp", 80, 34855)
        == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    )


def test_community_id_icmp_and_ipv6_and_errors():
    echo = community_id("10.0.0.1", "10.0.0.2", "icmp", 8, 0)
    reply = community_id("10.0.0.2", "10.0.0.1", "icmp", 0, 0)
    assert echo == reply and echo.startswith("1:")
    assert community_id("10.0.0.1", "10.0.0.2", "icmp", 3, 1) != echo  # one-way type
    assert community_id("fe80::1", "fe80::2", "icmp", 128, 0) == community_id(
        "fe80::2", "fe80::1", "icmp", 129, 0
    )
    assert community_id("fe80::1", "fe80::2", "udp", 1, 2).startswith("1:")
    assert community_id("fe80::1", "fe80::2", 47).startswith("1:")  # GRE: no ports
    assert community_id("10.0.0.1", "fe80::2", "tcp", 1, 2) is None
    assert community_id("nope", "10.0.0.2", "tcp", 1, 2) is None
    assert community_id("10.0.0.1", "10.0.0.2", "tcp", None, 2) is None
    assert community_id("10.0.0.1", "10.0.0.2", "bogus", 1, 2) is None


# -- connection ------------------------------------------------------------------------


def test_conn_record_maps_to_ecs():
    doc = to_ecs(CONN, "conn", {"observer": {"name": "sensor1"}})
    f = flat(doc)
    assert f["@timestamp"] == ISO
    assert f["event.created"] == ISO
    assert f["ecs.version"] == ECS_VERSION
    assert f["event.module"] == "zeek"
    assert f["event.dataset"] == "zeek.connection"
    assert f["event.kind"] == "event"
    assert f["event.category"] == ["network"]
    assert f["event.type"] == ["connection", "start", "end"]
    assert f["event.id"] == "CabcDEF123" and f["zeek.session_id"] == "CabcDEF123"
    assert f["event.duration"] == 1_250_000_000
    assert f["source.ip"] == "10.0.0.5" and f["source.address"] == "10.0.0.5"
    assert f["source.port"] == 51234 and f["destination.port"] == 443
    assert f["destination.ip"] == "93.184.216.34"
    assert f["source.bytes"] == 620 and f["destination.bytes"] == 2640
    assert f["source.packets"] == 10 and f["destination.packets"] == 12
    assert f["network.bytes"] == 3260 and f["network.packets"] == 22
    assert f["network.transport"] == "tcp" and f["network.protocol"] == "ssl"
    assert f["network.direction"] == "outbound"
    assert f["network.community_id"].startswith("1:")
    assert f["related.ip"] == ["10.0.0.5", "93.184.216.34"]
    assert f["tags"] == ["local_orig"]
    assert f["zeek.connection.state"] == "SF"
    assert f["zeek.connection.state_message"] == "Normal establishment and termination."
    assert f["zeek.connection.local_orig"] is True and f["zeek.connection.local_resp"] is False
    assert f["zeek.connection.history"] == "ShADadFf"
    assert f["observer.name"] == "sensor1"
    # dropped by the module and never emitted
    for gone in (
        "zeek.connection.orig_bytes",
        "zeek.connection.resp_bytes",
        "zeek.connection.tunnel_parents",
        "temp.duration",
        "zeek.connection.uid",
        "zeek.connection.id.orig_h",
    ):
        assert gone not in f
    assert "zeek.connection.ts" not in f


@pytest.mark.parametrize(
    ("orig", "resp", "direction"),
    [
        (True, True, "internal"),
        (False, True, "inbound"),
        (False, False, "external"),
        (None, True, None),
    ],
)
def test_conn_direction(orig, resp, direction):
    rec = dict(CONN, local_orig=orig, local_resp=resp)
    assert flat(to_ecs(rec, "conn")).get("network.direction") == direction


def test_conn_icmp_ports_become_type_and_code():
    rec = dict(CONN, proto="icmp", **{"id.orig_p": 8, "id.resp_p": 0}, conn_state="OTH")
    f = flat(to_ecs(rec, "conn"))
    assert "source.port" not in f and "destination.port" not in f
    assert f["zeek.connection.icmp.type"] == 8 and f["zeek.connection.icmp.code"] == 0
    assert f["network.community_id"] == community_id("10.0.0.5", "93.184.216.34", "icmp", 8, 0)
    assert f["event.type"] == ["connection", "info"]


def test_conn_unknown_state_and_missing_fields():
    rec = {
        "ts": TS,
        "uid": "C1",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 1,
        "id.resp_h": "10.0.0.6",
        "id.resp_p": 2,
        "proto": "udp",
        "conn_state": "??",
        "duration": None,
    }
    f = flat(to_ecs(rec, "conn"))
    assert "event.type" not in f and "zeek.connection.state_message" not in f
    assert "event.duration" not in f and "network.bytes" not in f and "tags" not in f
    assert f["zeek.connection.state"] == "??"


# -- dns -------------------------------------------------------------------------------


def test_dns_answer_record():
    rec = {
        "ts": TS,
        "uid": "Cdns",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 5353,
        "id.resp_h": "8.8.8.8",
        "id.resp_p": 53,
        "proto": "udp",
        "trans_id": 4660,
        "rtt": 0.02,
        "query": "www.example.com",
        "qclass": 1,
        "qclass_name": "C_INTERNET",
        "qtype": 1,
        "qtype_name": "A",
        "rcode": 0,
        "rcode_name": "NOERROR",
        "AA": False,
        "TC": False,
        "RD": True,
        "RA": True,
        "Z": 0,
        "answers": ["93.184.216.34", "cname.example.com"],
        "TTLs": [300.0, 60.0],
        "rejected": False,
    }
    f = flat(to_ecs(rec, "dns"))
    assert f["event.dataset"] == "zeek.dns"
    assert f["event.category"] == ["network"] and f["event.type"] == [
        "connection",
        "info",
        "protocol",
    ]
    assert f["dns.id"] == "4660"  # ECS dns.id is keyword
    assert f["dns.question.name"] == "www.example.com"
    assert f["dns.question.type"] == "A" and f["dns.question.class"] == "IN"
    assert f["dns.response_code"] == "NOERROR"
    assert f["dns.header_flags"] == ["RD", "RA"]
    assert f["dns.type"] == "answer"
    assert f["dns.resolved_ip"] == ["93.184.216.34"]
    assert f["event.duration"] == 20_000_000
    assert f["event.outcome"] == "success"
    assert (
        f["zeek.dns.trans_id"] == "4660" and f["zeek.dns.rtt"] == 0.02
    )  # Beats stores it as keyword
    assert "zeek.dns.Z" not in f
    doc = to_ecs(rec, "dns")
    assert doc["dns"]["answers"] == [
        {"data": "93.184.216.34", "ttl": 300},
        {"data": "cname.example.com", "ttl": 60},
    ]


def test_dns_query_only_and_failure():
    rec = {
        "ts": TS,
        "uid": "C",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 1,
        "id.resp_h": "10.0.0.53",
        "id.resp_p": 53,
        "proto": "udp",
        "query": "x",
        "qclass": 99,
        "rcode": 3,
        "rcode_name": None,
    }
    f = flat(to_ecs(rec, "dns"))
    assert f["dns.type"] == "query"
    assert f["dns.question.class"] == "99"
    assert f["event.outcome"] == "failure"
    assert "dns.header_flags" not in f and "dns.answers" not in f


# -- http / ssl / files / kerberos / ntlm / smb / notice / x509 / weird -------------------


def test_http_record():
    rec = {
        "ts": TS,
        "uid": "C",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 1,
        "id.resp_h": "10.0.0.6",
        "id.resp_p": 80,
        "method": "GET",
        "host": "example.com",
        "uri": "/x",
        "referrer": "http://r/",
        "version": "1.1",
        "user_agent": "curl/8",
        "status_code": 404,
        "username": "bob",
        "request_body_len": 0,
        "response_body_len": 12,
    }
    f = flat(to_ecs(rec, "http"))
    assert f["http.request.method"] == "GET" and f["event.action"] == "get"
    assert f["http.response.status_code"] == 404 and f["event.outcome"] == "failure"
    assert f["url.domain"] == "example.com" and f["url.original"] == "/x" and f["url.port"] == 80
    assert f["url.username"] == "bob" and f["user.name"] == "bob" and f["related.user"] == ["bob"]
    assert f["user_agent.original"] == "curl/8"
    assert f["http.request.referrer"] == "http://r/"
    assert f["event.category"] == ["network", "web"]


def test_ssl_record():
    rec = {
        "ts": TS,
        "uid": "C",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 1,
        "id.resp_h": "10.0.0.6",
        "id.resp_p": 443,
        "version": "TLSv12",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "curve": "x25519",
        "server_name": "example.com",
        "resumed": False,
        "established": True,
        "subject": "CN=example.com,O=Example\\, Inc,C=US",
        "issuer": "CN=R3,O=Let's Encrypt,C=US",
        "ja3": "abc",
        "ja3s": "def",
    }
    f = flat(to_ecs(rec, "ssl"))
    assert f["tls.version"] == "1.2" and f["tls.version_protocol"] == "tls"
    assert f["tls.cipher"] == "TLS_AES_128_GCM_SHA256" and f["tls.curve"] == "x25519"
    assert f["tls.established"] is True and f["tls.resumed"] is False
    assert (
        f["tls.client.server_name"] == "example.com" and f["zeek.ssl.server.name"] == "example.com"
    )
    assert f["tls.server.subject"] == "CN=example.com,O=Example\\, Inc,C=US"
    # ECS declares x509 subject/issuer attributes as arrays; the zeek.* copies are scalars
    assert f["tls.server.x509.subject.common_name"] == ["example.com"]
    assert f["tls.server.x509.subject.organization"] == ["Example Inc"]
    assert f["tls.server.x509.issuer.common_name"] == ["R3"]
    assert f["zeek.ssl.server.subject.country"] == "US"
    assert f["tls.client.ja3"] == "abc" and f["tls.server.ja3s"] == "def"
    assert flat(to_ecs(dict(rec, version="SSLv3"), "ssl"))["tls.version"] == "3.0"
    assert "tls.version" not in flat(to_ecs(dict(rec, version="weird"), "ssl"))


def test_files_record():
    rec = {
        "ts": TS,
        "fuid": "F1",
        "uid": "Cconn",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 1,
        "id.resp_h": "10.0.0.6",
        "id.resp_p": 2,
        "conn_uids": ["Cconn"],
        "tx_hosts": ["10.0.0.6"],
        "rx_hosts": ["10.0.0.5"],
        "source": "HTTP",
        "mime_type": "text/plain",
        "filename": "a.txt",
        "total_bytes": 12,
        "md5": "m",
        "sha1": "s1",
        "sha256": "s2",
        "x509": None,
    }
    f = flat(to_ecs(rec, "files"))
    assert f["event.category"] == ["file"] and f["event.type"] == ["info"]
    assert f["zeek.session_id"] == "Cconn" and f["event.id"] == "Cconn"
    assert f["zeek.files.session_ids"] == ["Cconn"]
    assert f["server.ip"] == "10.0.0.6" and f["client.ip"] == "10.0.0.5"
    assert f["zeek.files.tx_host"] == "10.0.0.6" and "zeek.files.tx_hosts" not in f
    assert set(f["related.ip"]) == {"10.0.0.5", "10.0.0.6"}
    assert (
        f["file.name"] == "a.txt" and f["file.size"] == 12 and f["file.mime_type"] == "text/plain"
    )
    assert f["file.hash.md5"] == "m" and f["related.hash"] == ["m", "s1", "s2"]


def test_kerberos_record():
    rec = {
        "ts": TS,
        "uid": "C",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 1,
        "id.resp_h": "10.0.0.6",
        "id.resp_p": 88,
        "request_type": "TGS",
        "client": "bob/CORP",
        "service": "krbtgt/CORP",
        "success": True,
        "till": TS + 86400 * 10,
        "from": TS,
        "cipher": "aes256",
        "forwardable": True,
        "renewable": True,
        "client_cert_subject": "CN=bob,OU=Users",
    }
    f = flat(to_ecs(rec, "kerberos"))
    assert f["event.action"] == "TGS" and f["event.outcome"] == "success"
    assert f["zeek.kerberos.valid.days"] == 10
    assert f["client.address"] == "10.0.0.5" and f["server.address"] == "10.0.0.6"
    assert f["tls.client.x509.subject.common_name"] == ["bob"]
    assert f["zeek.kerberos.cert.client.subject"] == "CN=bob,OU=Users"
    assert "zeek.kerberos.client_cert_subject" not in f
    assert f["event.type"] == ["connection", "protocol", "authentication"]
    assert flat(to_ecs(dict(rec, success=False), "kerberos"))["event.outcome"] == "failure"


def test_ntlm_and_smb_and_weird_and_notice():
    ntlm = {
        "ts": TS,
        "uid": "C",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 1,
        "id.resp_h": "10.0.0.6",
        "id.resp_p": 445,
        "username": "bob",
        "hostname": "WS1",
        "domainname": "CORP",
        "success": True,
    }
    f = flat(to_ecs(ntlm, "ntlm"))
    assert f["user.name"] == "bob" and f["user.domain"] == "CORP" and f["related.user"] == ["bob"]
    assert f["event.category"] == ["authentication", "network"]

    smb = {
        "ts": TS,
        "uid": "C",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 1,
        "id.resp_h": "10.0.0.6",
        "id.resp_p": 445,
        "fuid": "F",
        "action": "SMB::FILE_DELETE",
        "path": "\\\\srv\\share",
        "name": "doc.txt",
        "size": 5,
        "times.modified": TS,
        "times.accessed": TS,
        "times.created": TS,
        "times.changed": TS,
    }
    f = flat(to_ecs(smb, "smb_files"))
    assert f["event.action"] == "SMB::FILE_DELETE" and f["event.type"] == [
        "connection",
        "protocol",
        "deletion",
    ]
    assert f["file.name"] == "doc.txt" and f["file.size"] == 5
    assert f["file.path"] == "\\\\srv\\share\\doc.txt"
    assert (
        f["file.mtime"] == ISO
        and f["file.created"] == ISO
        and f["file.accessed"] == ISO
        and f["file.ctime"] == ISO
    )
    assert f["zeek.smb_files.times.modified"] == ISO  # zeek.* date field coerced too
    f2 = flat(to_ecs(dict(smb, action="SMB::FILE_OPEN"), "smb_files"))
    assert f2["event.type"][-1] == "info"

    weird = {
        "ts": TS,
        "uid": "C",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 1,
        "id.resp_h": "10.0.0.6",
        "id.resp_p": 2,
        "name": "bad_TCP_checksum",
        "notice": False,
        "peer": "zeek",
        "source": "TCP",
    }
    f = flat(to_ecs(weird, "weird"))
    assert f["rule.name"] == "bad_TCP_checksum" and f["event.kind"] == "alert"

    notice = {
        "ts": TS,
        "uid": "C",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 1,
        "id.resp_h": "10.0.0.6",
        "id.resp_p": 2,
        "note": "Scan::Port_Scan",
        "msg": "scanned",
        "src": "10.0.0.5",
        "dst": "10.0.0.6",
        "p": 2,
        "actions": ["Notice::ACTION_LOG"],
        "dropped": False,
        "suppress_for": 3600.0,
    }
    f = flat(to_ecs(notice, "notice"))
    assert f["rule.name"] == "Scan::Port_Scan" and f["rule.description"] == "scanned"
    assert f["event.kind"] == "alert" and f["event.category"] == ["intrusion_detection"]
    assert f["event.type"] == ["info", "allowed"]
    assert "zeek.notice.actions" not in f


def test_x509_record():
    rec = {
        "ts": TS,
        "id": "F1",
        "certificate.version": 3,
        "certificate.serial": "0A1B",
        "certificate.subject": "CN=example.com,O=Example",
        "certificate.issuer": "CN=R3,O=Let's Encrypt",
        "certificate.not_valid_before": TS,
        "certificate.not_valid_after": TS + 86400,
        "certificate.key_alg": "rsaEncryption",
        "certificate.sig_alg": "sha256WithRSAEncryption",
        "certificate.key_type": "rsa",
        "certificate.key_length": 2048,
        "certificate.exponent": "65537",
        "san.dns": ["example.com", "www.example.com"],
        "san.ip": ["10.0.0.1"],
        "basic_constraints.ca": False,
    }
    f = flat(to_ecs(rec, "x509"))
    assert (
        f["event.dataset"] == "zeek.x509" and f["zeek.session_id"] == "F1" and f["event.id"] == "F1"
    )
    assert f["file.x509.signature_algorithm"] == "SHA256-RSA"
    assert (
        f["file.x509.public_key_algorithm"] == "rsaEncryption"
        and f["file.x509.public_key_size"] == 2048
    )
    assert f["file.x509.public_key_exponent"] == 65537
    assert f["file.x509.serial_number"] == "0A1B" and f["file.x509.version_number"] == "3"
    assert f["file.x509.alternative_names"] == ["example.com", "www.example.com", "10.0.0.1"]
    assert f["file.x509.not_before"] == ISO and f["zeek.x509.certificate.valid.from"] == ISO
    assert f["file.x509.subject.common_name"] == ["example.com"]
    assert f["file.x509.issuer.organization"] == ["Let's Encrypt"]
    assert f["zeek.x509.certificate.issuer.common_name"] == "R3"
    assert "zeek.x509.certificate.iss" not in f and "zeek.x509.certificate.sub" not in f
    assert f["zeek.x509.basic_constraints.certificate_authority"] is False


def test_other_filesets_outcomes():
    base = {
        "ts": TS,
        "uid": "C",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 1,
        "id.resp_h": "10.0.0.6",
        "id.resp_p": 2,
    }
    assert (
        flat(to_ecs(dict(base, auth_success=False, **{"auth.success": False}), "ssh"))[
            "event.outcome"
        ]
        == "failure"
    )
    assert flat(to_ecs(dict(base, **{"auth.success": True}), "ssh"))["event.outcome"] == "success"
    assert flat(to_ecs(dict(base, ssl=True, cookie="x"), "rdp"))["tls.established"] is True
    f = flat(to_ecs(dict(base, command="READ", status="ACCESS_DENIED", username="bob"), "smb_cmd"))
    assert f["event.type"][-1] == "error" and f["user.name"] == "bob"
    assert flat(to_ecs(dict(base, status="SUCCESS"), "smb_cmd"))["event.outcome"] == "success"
    assert flat(to_ecs(dict(base, status="succeeded"), "socks"))["event.outcome"] == "success"
    assert flat(to_ecs(dict(base, status="failed"), "socks"))["event.type"][-1] == "error"
    f = flat(to_ecs(dict(base, **{"status_code": 404}), "sip"))
    assert f["event.outcome"] == "failure" and f["event.type"][-1] == "error"
    assert flat(to_ecs(dict(base, cmd="connect"), "mysql"))["event.type"] == [
        "connection",
        "protocol",
        "access",
        "start",
    ]
    assert flat(to_ecs(dict(base, cmd="drop_db"), "mysql"))["event.type"][-1] == "change"
    assert flat(to_ecs(dict(base, cmd="query"), "mysql"))["event.type"][-1] == "info"
    f = flat(
        to_ecs(
            {
                "ts": TS,
                "ts_delta": 900.0,
                "peer": "zeek",
                "gaps": 0,
                "acks": 10,
                "percent_lost": 0.0,
            },
            "capture_loss",
        )
    )
    assert (
        f["event.kind"] == "metric"
        and f["event.type"] == ["info"]
        and f["zeek.capture_loss.percent_lost"] == 0.0
    )


def test_unknown_log_gets_generic_mapping():
    rec = {
        "ts": TS,
        "host": "10.0.0.5",
        "software_type": "HTTP::BROWSER",
        "name": "Firefox",
        "version.major": 100,
        "unparsed_version": "Firefox/100",
    }
    f = flat(to_ecs(rec, "software"))
    assert (
        f["event.dataset"] == "zeek.software"
        and f["event.kind"] == "event"
        and f["event.type"] == ["info"]
    )
    assert f["zeek.software.name"] == "Firefox" and f["zeek.software.version.major"] == 100
    assert "event.category" not in f
    rec2 = {
        "ts": TS,
        "uid": "C",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 1,
        "id.resp_h": "10.0.0.6",
        "id.resp_p": 389,
        "proto": "tcp",
        "message_id": 1,
    }
    f2 = flat(to_ecs(rec2, "ldap"))
    assert f2["source.ip"] == "10.0.0.5" and f2["destination.port"] == 389 and f2["event.id"] == "C"
    assert f2["event.category"] == ["network"] and f2["network.community_id"].startswith("1:")
    assert flat(to_ecs({"a": 1}, None))["event.dataset"] == "zeek.unknown"


# -- types -----------------------------------------------------------------------------


def test_type_coercion_follows_ecs():
    rec = {
        "ts": str(TS),
        "uid": 12345,
        "id.orig_h": " 10.0.0.5 ",
        "id.orig_p": "51234",
        "id.resp_h": "not-an-ip",
        "id.resp_p": 443.0,
        "proto": "tcp",
        "conn_state": "SF",
        "local_orig": "T",
        "orig_pkts": "3",
        "resp_pkts": 4.0,
        "missed_bytes": "0x10",
    }
    f = flat(to_ecs(rec, "conn"))
    assert f["@timestamp"] == ISO
    assert f["event.id"] == "12345" and f["zeek.session_id"] == "12345"  # keyword
    assert (
        f["source.ip"] == "10.0.0.5" and f["source.port"] == 51234 and f["destination.port"] == 443
    )
    assert "destination.ip" not in f and f["destination.address"] == "not-an-ip"
    assert f["related.ip"] == ["10.0.0.5"]
    assert f["zeek.connection.local_orig"] is True and f["tags"] == ["local_orig"]
    assert f["source.packets"] == 3 and f["destination.packets"] == 4 and f["network.packets"] == 7
    assert f["zeek.connection.missed_bytes"] == 16
    assert isinstance(f["event.category"], list)


def test_meta_is_nested_and_arrays_wrapped():
    doc = to_ecs(
        dict(CONN), "conn", {"observer.name": "s", "tags": "extra", "event.type": "custom"}
    )
    assert doc["observer"]["name"] == "s"
    assert doc["tags"] == ["extra"]  # meta wins over the derived tag and is wrapped
    assert doc["event"]["type"] == ["custom"]


def test_datetime_timestamps_accepted():
    rec = dict(CONN, ts=datetime(2020, 9, 13, 12, 26, 40, 500000, tzinfo=timezone.utc))
    assert to_ecs(rec, "conn")["@timestamp"] == ISO


def test_unflatten_conflicts():
    assert unflatten({"a.b": 1, "a.c": 2, "d": 3}) == {"a": {"b": 1, "c": 2}, "d": 3}
    assert unflatten({"a": 1, "a.b": 2}) == {"a": {"value": 1, "b": 2}}
    assert unflatten({"a.b": 2, "a": 1}) == {"a": {"value": 1, "b": 2}}


def _check_types(f, name):
    checks = {
        "long": int,
        "integer": int,
        "double": float,
        "float": float,
        "boolean": bool,
        "ip": str,
        "date": str,
        "keyword": str,
        "text": str,
        "wildcard": str,
        "match_only_text": str,
    }
    for key, value in f.items():
        assert value is not None, (name, key)
        ftype = FIELD_TYPES.get(key)
        if ftype in checks:
            expected = checks[ftype]
            values = value if isinstance(value, list) else [value]
            for v in values:
                assert isinstance(v, expected) and not (expected is int and isinstance(v, bool)), (
                    name,
                    key,
                    ftype,
                    v,
                )
        if key in ARRAY_FIELDS:
            assert isinstance(value, list), (name, key)


def test_fixture_corpus_produces_typed_documents(data_dir):
    seen_datasets = set()
    for path in sorted((data_dir / "rdp_sharprdp" / "tsv").glob("*.log")):
        with_records = 0
        for record in read_zeek(path):
            doc = to_ecs(record, path.stem)
            f = flat(doc)
            with_records += 1
            assert f["@timestamp"] and f["ecs.version"] == ECS_VERSION
            assert f["event.dataset"].startswith("zeek.")
            seen_datasets.add(f["event.dataset"])
            _check_types(f, path.name)
            json.dumps(doc)  # serialisable
        assert with_records > 0, path
    assert {"zeek.connection", "zeek.rdp", "zeek.dns", "zeek.notice"} <= seen_datasets
    for record in read_zeek(data_dir / "rdp_sharprdp" / "json" / "conn.log"):
        _check_types(flat(to_ecs(record, "conn")), "json conn")


def test_index_body_mirrors_field_table():
    props = ecs_index_body()["mappings"]["properties"]
    assert props["@timestamp"] == {"type": "date"}
    assert props["source"]["properties"]["ip"] == {"type": "ip"}
    assert props["event"]["properties"]["duration"] == {"type": "long"}
    assert props["event"]["properties"]["category"] == {"type": "keyword"}
    assert props["dns"]["properties"]["answers"]["properties"]["ttl"] == {"type": "long"}
    assert props["zeek"]["properties"]["connection"]["properties"]["state"] == {"type": "keyword"}
    assert props["zeek"]["properties"]["session_id"] == {"type": "keyword"}
    assert props["tags"] == {"type": "keyword"}

    def walk(node, prefix=""):
        for name, spec in node.items():
            assert "type" in spec, prefix + name
            if "properties" in spec:
                assert spec["type"] in ("object", "nested"), prefix + name
                walk(spec["properties"], prefix + name + ".")

    walk(props)
