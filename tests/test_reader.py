import gzip
import io
import json
from datetime import datetime, timezone

import pytest

from parsezeeklogs.reader import (
    ZeekHeader,
    ZeekLog,
    convert_value,
    decode_escapes,
    read_zeek,
    safe_name,
    to_json,
    write_csv,
    write_json_lines,
)

HEADER = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tdemo\n"
    "#open\t2026-09-05-12-00-00\n"
)


#: Logs whose values describe the Zeek run itself (CPU, memory, wall-clock start)
#: and therefore differ between the TSV and JSON passes.
RUN_DEPENDENT_LOGS = frozenset({"telemetry.log", "stats.log", "packet_filter.log"})


def tsv(fields: str, types: str, *rows: str) -> io.StringIO:
    text = HEADER + f"#fields\t{fields}\n#types\t{types}\n" + "".join(r + "\n" for r in rows)
    return io.StringIO(text)


# -- helpers ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("plain", "plain"),
        ("a\\x09b", "a\tb"),
        ("back\\x5cslash", "back\\slash"),
        ("caf\\xc3\\xa9", "café"),
        ("comma\\x2chere", "comma,here"),
        ("bad\\xff", "bad\ufffd"),
        # Zeek writes a literal backslash as two backslashes, so a UNC path round-trips
        ("\\\\\\\\10.0.0.1\\\\IPC$", "\\\\10.0.0.1\\IPC$"),
        # ...and text that itself contains "\\x01" (NetBIOS names) is not mis-decoded
        ("\\\\x01\\\\x02__MSBROWSE__\\\\x02", "\\x01\\x02__MSBROWSE__\\x02"),
        ("no escapes \\\\ here", "no escapes \\ here"),
    ],
)
def test_decode_escapes(raw, expected):
    assert decode_escapes(raw) == expected


def test_safe_name():
    assert safe_name("id.orig_h") == "id_orig_h"
    assert safe_name("plain") == "plain"


@pytest.mark.parametrize(
    ("value", "ztype", "expected"),
    [
        ("42", "count", 42),
        ("-7", "int", -7),
        ("443", "port", 443),
        ("1.5", "double", 1.5),
        ("0.25", "interval", 0.25),
        ("1600000000.5", "time", 1600000000.5),
        ("T", "bool", True),
        ("F", "bool", False),
        ("10.0.0.1", "addr", "10.0.0.1"),
        ("10.0.0.0/8", "subnet", "10.0.0.0/8"),
        ("tcp", "enum", "tcp"),
        ("(empty)", "string", ""),
        ("-", "string", None),
        ("-", "count", None),
        ("-", "bool", None),
        ("a,b\\x2cc", "set[string]", ["a", "b,c"]),
        ("1,2,3", "vector[count]", [1, 2, 3]),
        ("1.0,2.5", "vector[interval]", [1.0, 2.5]),
        ("(empty)", "set[string]", []),
        ("-", "vector[string]", None),
        ("-,x", "vector[string]", [None, "x"]),
    ],
)
def test_convert_value(value, ztype, expected):
    assert convert_value(value, ztype, ZeekHeader(), "epoch") == expected


def test_convert_time_formats():
    header = ZeekHeader()
    assert convert_value("0", "time", header, "iso") == "1970-01-01T00:00:00+00:00"
    assert convert_value("0", "time", header, "datetime") == datetime(
        1970, 1, 1, tzinfo=timezone.utc
    )
    assert convert_value("-", "time", header, "iso") is None


def test_convert_rejects_bad_numbers():
    header = ZeekHeader()
    with pytest.raises(ValueError):
        convert_value("x", "count", header, "epoch")


# -- header ----------------------------------------------------------------------------


def test_header_directives_and_custom_separators():
    src = io.StringIO(
        "#separator \\x7c\n"
        "#set_separator|;\n"
        "#empty_field|EMPTY\n"
        "#unset_field|NULL\n"
        "#path|weird\n"
        "#fields|a|b|c\n"
        "#types|count|set[string]|string\n"
        "1|x;y|EMPTY\n"
        "NULL|EMPTY|hi\n"
    )
    log = ZeekLog(src)
    assert log.header.separator == "|"
    assert log.header.set_separator == ";"
    assert log.header.directives["path"] == "weird"
    assert log.path == "weird"
    assert log.fields == ["a", "b", "c"]
    assert log.types == {"a": "count", "b": "set[string]", "c": "string"}
    assert list(log) == [{"a": 1, "b": ["x", "y"], "c": ""}, {"a": None, "b": [], "c": "hi"}]


def test_header_missing_fields_is_an_error():
    src = io.StringIO("#separator \\x09\n#path\tx\n")
    with pytest.raises(ValueError, match="no #fields"):
        ZeekLog(src)


def test_header_fields_types_mismatch_is_an_error():
    src = io.StringIO("#separator \\x09\n#fields\ta\tb\n#types\tcount\n")
    with pytest.raises(ValueError, match="disagree"):
        ZeekLog(src)


def test_header_repeated_mid_stream_is_reparsed():
    """Rotated logs concatenated together carry a fresh header block in the middle."""
    part1 = tsv("a\tb", "count\tstring", "1\tx", "#close\t2026-09-05-12-00-01").getvalue()
    part2 = tsv("a\tb\tc", "count\tstring\tbool", "2\ty\tT").getvalue()
    log = ZeekLog(io.StringIO(part1 + part2))
    assert list(log) == [{"a": 1, "b": "x"}, {"a": 2, "b": "y", "c": True}]
    assert log.skipped == 0


def test_leading_blank_lines_are_ignored():
    src = io.StringIO("\n\n" + tsv("a", "count", "5").getvalue())
    assert list(ZeekLog(src)) == [{"a": 5}]


# -- records ---------------------------------------------------------------------------


def test_records_full_conversion():
    log = ZeekLog(
        tsv(
            "ts\tuid\tid.orig_h\tid.orig_p\tproto\tduration\tlocal_orig\ttunnel_parents\tnote",
            "time\tstring\taddr\tport\tenum\tinterval\tbool\tset[string]\tstring",
            "1600000000.123456\tCabc\t10.0.0.1\t51234\ttcp\t0.5\tT\t(empty)\thello\\x09world",
            "1600000001.0\tCdef\t10.0.0.2\t80\tudp\t-\tF\ta,b\t-",
        )
    )
    assert list(log) == [
        {
            "ts": 1600000000.123456,
            "uid": "Cabc",
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 51234,
            "proto": "tcp",
            "duration": 0.5,
            "local_orig": True,
            "tunnel_parents": [],
            "note": "hello\tworld",
        },
        {
            "ts": 1600000001.0,
            "uid": "Cdef",
            "id.orig_h": "10.0.0.2",
            "id.orig_p": 80,
            "proto": "udp",
            "duration": None,
            "local_orig": False,
            "tunnel_parents": ["a", "b"],
            "note": None,
        },
    ]


def test_fields_filter_and_safe_headers():
    src = tsv("ts\tid.orig_h\tid.resp_p", "time\taddr\tport", "1.0\t10.0.0.1\t443")
    log = ZeekLog(src, fields=["id.orig_h", "id_resp_p"], safe_headers=True)
    assert log.fields == ["id_orig_h", "id_resp_p"]
    assert log.types == {"id_orig_h": "addr", "id_resp_p": "port"}
    assert list(log) == [{"id_orig_h": "10.0.0.1", "id_resp_p": 443}]


def test_meta_is_merged_into_every_record():
    log = ZeekLog(tsv("a", "count", "1", "2"), meta={"sensor": "dmz"})
    assert list(log) == [{"a": 1, "sensor": "dmz"}, {"a": 2, "sensor": "dmz"}]


def test_time_format_iso_on_tsv():
    log = ZeekLog(tsv("ts", "time", "0"), time_format="iso")
    assert list(log) == [{"ts": "1970-01-01T00:00:00+00:00"}]


def test_wrong_column_count_is_skipped_and_reported():
    seen = []
    log = ZeekLog(
        tsv("a\tb", "count\tstring", "1\tx", "only-one-column", "3\tz"),
        on_error=lambda n, line, exc: seen.append((n, line, str(exc))),
    )
    assert list(log) == [{"a": 1, "b": "x"}, {"a": 3, "b": "z"}]
    assert log.skipped == 1
    assert seen[0][0] == 10  # 8 header lines + 2 data lines
    assert seen[0][1] == "only-one-column"
    assert "expected 2 columns" in seen[0][2]


def test_unparseable_value_is_skipped_and_reported(caplog):
    log = ZeekLog(tsv("a", "count", "1", "notanumber", "3"))
    assert list(log) == [{"a": 1}, {"a": 3}]
    assert log.skipped == 1
    assert "skipped" in caplog.text


def test_blank_lines_in_body_are_ignored():
    assert list(ZeekLog(tsv("a", "count", "1", "", "2"))) == [{"a": 1}, {"a": 2}]


# -- JSON logs -------------------------------------------------------------------------


def test_json_log_detected_and_passed_through():
    src = io.StringIO(
        '{"ts": 1.5, "id.orig_h": "10.0.0.1", "answers": ["a", "b"], "ok": true}\n'
        "not json\n"
        "[1, 2]\n"
        '{"ts": 2.5, "id.orig_h": "10.0.0.2"}\n'
    )
    seen = []
    log = ZeekLog(src, on_error=lambda n, line, exc: seen.append(line))
    assert log.is_json
    assert log.header is None
    assert log.fields == []
    assert log.types == {}
    assert log.path is None
    assert list(log) == [
        {"ts": 1.5, "id.orig_h": "10.0.0.1", "answers": ["a", "b"], "ok": True},
        {"ts": 2.5, "id.orig_h": "10.0.0.2"},
    ]
    assert seen == ["not json", "[1, 2]"]
    assert log.skipped == 2


def test_json_log_options():
    src = io.StringIO('{"ts": 0, "id.orig_h": "10.0.0.1", "uid": "C1"}\n')
    log = ZeekLog(
        src, fields=["ts", "id_orig_h"], safe_headers=True, time_format="iso", meta={"m": 1}
    )
    assert list(log) == [{"ts": "1970-01-01T00:00:00+00:00", "id_orig_h": "10.0.0.1", "m": 1}]


def test_json_path_comes_from_file_name(tmp_path):
    p = tmp_path / "dns.log"
    p.write_text('{"ts": 1}\n')
    assert ZeekLog(p).path == "dns"
    q = tmp_path / "http.json"
    q.write_text('{"ts": 1}\n')
    assert ZeekLog(q).path == "http"


# -- files -----------------------------------------------------------------------------


def test_gzip_files_are_transparent(tmp_path):
    p = tmp_path / "conn.log.gz"
    with gzip.open(p, "wt", encoding="utf-8") as fh:
        fh.write(tsv("a", "count", "7").getvalue())
    with ZeekLog(p) as log:
        assert log.path == "demo"
        assert list(log) == [{"a": 7}]


def test_read_zeek_closes_the_file(tmp_path):
    p = tmp_path / "x.log"
    p.write_text(tsv("a", "count", "1").getvalue())
    assert list(read_zeek(p, meta={"k": "v"})) == [{"a": 1, "k": "v"}]


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        ZeekLog("/nonexistent/conn.log")


def test_legacy_conn_log_parses_completely(data_dir):
    with ZeekLog(data_dir / "conn_2018.log") as log:
        assert log.path == "conn"
        assert log.types["ts"] == "time"
        assert log.types["tunnel_parents"] == "set[string]"
        records = list(log)
    assert len(records) == 2164
    assert log.skipped == 0
    first = records[0]
    assert first["id.orig_p"] == 137
    assert first["duration"] == pytest.approx(3.748891)
    assert first["local_orig"] is None  # unset in this old log
    assert first["tunnel_parents"] is None
    assert all(isinstance(r["ts"], float) for r in records)
    assert all(isinstance(r["orig_pkts"], int) for r in records)


def test_zeek8_tsv_and_json_agree(data_dir):
    """The same capture rendered by Zeek 8.2.2 in both formats must parse to equal records."""
    for tsv_path in sorted((data_dir / "rdp_sharprdp" / "tsv").glob("*.log")):
        if tsv_path.name in RUN_DEPENDENT_LOGS:
            continue
        json_path = data_dir / "rdp_sharprdp" / "json" / tsv_path.name
        tsv_records = list(read_zeek(tsv_path))
        json_records = list(read_zeek(json_path))
        assert len(tsv_records) == len(json_records), tsv_path.name
        for a, b in zip(tsv_records, json_records, strict=True):
            _assert_equivalent(a, b, tsv_path.name)


def _decode(value):
    if isinstance(value, str):
        return decode_escapes(value)
    if isinstance(value, list):
        return [decode_escapes(v) if isinstance(v, str) else v for v in value]
    return value


def _assert_equivalent(tsv_rec, json_rec, name):
    """JSON omits unset fields and keeps full float precision; TSV rounds to 6 decimals.

    TSV also cannot tell an empty set from a set holding one empty string (both
    are ``(empty)``), so ``[]`` and ``[""]`` are treated as equal.
    """
    for key, value in tsv_rec.items():
        if value is None:
            assert key not in json_rec, (name, key)
            continue
        assert key in json_rec, (name, key)
        other = json_rec[key]
        if (
            isinstance(value, float)
            or isinstance(value, list)
            and value
            and isinstance(value[0], float)
        ):
            assert other == pytest.approx(value, abs=1e-6), (name, key)
        elif value == [] and other == [""]:
            continue
        elif other != value:
            # Zeek's JSON writer leaves non-printable bytes as literal "\\xHH" text.
            assert _decode(other) == value, (name, key)
    assert set(json_rec) <= set(tsv_rec), name


def test_dns_vectors_from_zeek8(data_dir):
    records = list(read_zeek(data_dir / "c2_dns_txt" / "tsv" / "dns.log"))
    with_answers = [r for r in records if r["answers"]]
    assert with_answers, "expected at least one answered query"
    rec = with_answers[0]
    assert isinstance(rec["answers"], list)
    assert all(isinstance(a, str) for a in rec["answers"])
    assert isinstance(rec["TTLs"], list)
    assert all(isinstance(t, float) for t in rec["TTLs"])
    assert len(rec["answers"]) == len(rec["TTLs"])


# -- writers ---------------------------------------------------------------------------


def test_to_json_handles_datetimes():
    out = json.loads(to_json({"ts": datetime(1970, 1, 1, tzinfo=timezone.utc), "n": None}))
    assert out == {"ts": "1970-01-01T00:00:00+00:00", "n": None}


def test_to_json_rejects_unknown_types():
    with pytest.raises(TypeError):
        to_json({"x": object()})


def test_write_json_lines_counts():
    buf = io.StringIO()
    assert write_json_lines([{"a": 1}, {"a": 2}], buf) == 2
    assert buf.getvalue() == '{"a": 1}\n{"a": 2}\n'


def test_write_csv_formats_values():
    buf = io.StringIO()
    n = write_csv(
        [
            {"a": 1, "b": None, "c": [1, None, "x"], "d": True, "e": "q,q"},
            {"a": 2, "b": "s", "c": [], "d": False, "e": datetime(1970, 1, 1, tzinfo=timezone.utc)},
        ],
        buf,
    )
    assert n == 2
    assert buf.getvalue().splitlines() == [
        "a,b,c,d,e",
        '1,,"1,,x",T,"q,q"',
        "2,s,,F,1970-01-01T00:00:00+00:00",
    ]


def test_write_csv_explicit_fields_and_no_header():
    buf = io.StringIO()
    write_csv([{"a": 1, "b": 2}], buf, fields=["b", "missing"], header=False)
    assert buf.getvalue() == "2,\n"


def test_write_csv_header_only_when_no_records():
    buf = io.StringIO()
    assert write_csv([], buf, fields=["a", "b"]) == 0
    assert buf.getvalue() == "a,b\n"
    empty = io.StringIO()
    assert write_csv([], empty) == 0
    assert empty.getvalue() == ""


def test_header_only_log_yields_nothing_and_iterates_once():
    src = io.StringIO("#separator \\x09\n#fields\ta\n#types\tcount\n")
    log = ZeekLog(src)
    assert list(log) == []
    assert list(log) == []  # a second pass finds the stream exhausted
    assert log.fields == ["a"]


def test_borrowed_stream_is_not_closed():
    src = tsv("a", "count", "5")
    log = ZeekLog(src)
    assert [r["a"] for r in log] == [5]
    log.close()
    assert not src.closed
