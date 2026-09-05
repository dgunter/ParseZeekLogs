from datetime import datetime, timezone
from unittest import mock

import pytest

from parsezeeklogs import elastic
from parsezeeklogs.elastic import (
    INDEX_BODY,
    LoadResult,
    ZeekToElk,
    ensure_index,
    make_client,
    normalize_url,
    to_document,
)

# Placeholder credential for argument-passing tests; nothing authenticates against it.
BASIC_AUTH_SECRET = "pw"


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("localhost", "http://localhost:9200"),
        ("127.0.0.1", "http://127.0.0.1:9200"),
        ("10.0.0.5:9201", "http://10.0.0.5:9201"),
        ("https://es.example.com", "https://es.example.com"),
        ("http://u:p@es.example.com", "http://u:p@es.example.com:9200"),
        ("http://u@es.example.com", "http://u@es.example.com:9200"),
    ],
)
def test_normalize_url(given, expected):
    assert normalize_url(given) == expected


def test_make_client_kwargs():
    with mock.patch("elasticsearch.Elasticsearch") as es_cls:
        make_client("localhost")
        es_cls.assert_called_once_with("http://localhost:9200", request_timeout=60)
        es_cls.reset_mock()
        make_client(
            "https://es:9200",
            user="elastic",
            password=BASIC_AUTH_SECRET,
            api_key="k",
            ca_certs="ca.pem",
            verify_certs=False,
            timeout=5,
        )
    es_cls.assert_called_once_with(
        "https://es:9200",
        request_timeout=5,
        basic_auth=("elastic", BASIC_AUTH_SECRET),
        api_key="k",
        ca_certs="ca.pem",
        verify_certs=False,
        ssl_show_warn=False,
    )


def test_ensure_index():
    es = mock.Mock()
    es.indices.exists.return_value = False
    assert ensure_index(es, "zeeklogs") is True
    es.indices.create.assert_called_once_with(index="zeeklogs", **INDEX_BODY)
    es.indices.exists.return_value = True
    assert ensure_index(es, "zeeklogs") is False


def test_index_mapping_essentials():
    props = INDEX_BODY["mappings"]["properties"]
    assert INDEX_BODY["mappings"]["date_detection"] is False
    assert props["@timestamp"] == {"type": "date"}
    assert props["id"]["properties"]["orig_h"] == {"type": "ip"}


def test_to_document_variants():
    assert to_document({"ts": 0.0, "a": 1}, "conn") == {
        "ts": 0.0,
        "a": 1,
        "@timestamp": "1970-01-01T00:00:00+00:00",
        "@path": "conn",
    }
    dt = datetime(1970, 1, 1, tzinfo=timezone.utc)
    doc = to_document({"ts": dt})
    assert doc["@timestamp"] == "1970-01-01T00:00:00+00:00"
    assert doc["ts"] == 0.0
    assert to_document({"ts": "2020-01-01T00:00:00Z"})["@timestamp"] == "2020-01-01T00:00:00Z"
    assert "@timestamp" not in to_document({"x": 1})
    assert "@path" not in to_document({"x": 1}, None)


def test_actions_and_load(data_dir):
    es = mock.Mock()
    result = LoadResult()
    tool = ZeekToElk(es, index="idx", metadata={"case": "1"}, fields=["ts", "uid"])
    actions = list(tool.actions(str(data_dir / "rdp_sharprdp" / "tsv" / "rdp.log"), result))
    assert actions
    src = actions[0]["_source"]
    assert actions[0]["_index"] == "idx"
    assert src["@path"] == "rdp"
    assert src["case"] == "1"
    assert set(src) == {"ts", "uid", "case", "@timestamp", "@path"}

    def fake_streaming_bulk(client, acts, **kwargs):
        assert kwargs["chunk_size"] == 3
        for i, _a in enumerate(acts):
            yield (i % 2 == 0), {"index": {"error": f"bad {i}"}}

    with mock.patch("elasticsearch.helpers.streaming_bulk", fake_streaming_bulk):
        res = ZeekToElk(es, bulk_size=3, max_error_samples=2).load_many(
            [
                str(data_dir / "rdp_sharprdp" / "tsv" / "rdp.log"),
                str(data_dir / "rdp_sharprdp" / "tsv" / "conn.log"),
            ]
        )
    assert res.indexed + res.failed == len(
        list(ZeekToElk(es).actions(str(data_dir / "rdp_sharprdp" / "tsv" / "rdp.log")))
    ) + len(list(ZeekToElk(es).actions(str(data_dir / "rdp_sharprdp" / "tsv" / "conn.log"))))
    assert res.failed > 0
    assert not res.ok
    assert len(res.errors) == 2


def test_bulk_size_minimum():
    assert ZeekToElk(mock.Mock(), bulk_size=0).bulk_size == 1


def test_skipped_lines_counted(tmp_path):
    p = tmp_path / "conn.log"
    p.write_text("#separator \\x09\n#fields\ta\n#types\tcount\n1\nbad\n2\n")
    result = LoadResult()
    docs = list(ZeekToElk(mock.Mock()).actions(str(p), result))
    assert len(docs) == 2
    assert result.skipped == 1


def test_missing_extra_gives_clear_error(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "elasticsearch":
            raise ImportError("no module")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ImportError, match=r"parsezeeklogs\[elasticsearch\]"):
        elastic._require_elasticsearch()


def test_ensure_index_ecs_uses_generated_mapping():
    es = mock.Mock()
    es.indices.exists.return_value = False
    assert ensure_index(es, "ecs-idx", ecs=True) is True
    body = es.indices.create.call_args.kwargs
    assert body["index"] == "ecs-idx"
    assert body["mappings"]["properties"]["source"]["properties"]["ip"] == {"type": "ip"}


def test_actions_in_ecs_mode(data_dir):
    es = mock.Mock()
    tool = ZeekToElk(es, index="idx", metadata={"observer.name": "s"}, ecs=True)
    action = next(tool.actions(str(data_dir / "rdp_sharprdp" / "tsv" / "conn.log")))
    src = action["_source"]
    assert src["event"]["dataset"] == "zeek.connection"
    assert src["observer"]["name"] == "s"
    assert "@path" not in src
    assert "ts" not in src
