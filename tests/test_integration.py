"""End-to-end tests against a live Elasticsearch (``docker compose up -d --wait``)."""

import uuid

import pytest

from parsezeeklogs import ParseZeekLogs
from parsezeeklogs.cli import main
from parsezeeklogs.elastic import ZeekToElk, ensure_index, make_client

pytestmark = pytest.mark.integration


@pytest.fixture
def es(es_url):
    client = make_client(es_url)
    yield client
    client.close()


@pytest.fixture
def index(es):
    name = f"parsezeeklogs-test-{uuid.uuid4().hex[:8]}"
    yield name
    es.indices.delete(index=name, ignore_unavailable=True)


def _count(es, index, **query):
    es.indices.refresh(index=index)
    return es.count(index=index, **query)["count"]


def test_load_capture_logs_with_mapping(es, index, data_dir):
    assert ensure_index(es, index)
    paths = sorted(str(p) for p in (data_dir / "rdp_sharprdp" / "tsv").glob("*.log"))
    result = ZeekToElk(es, index=index, metadata={"case": "it"}).load_many(paths)
    assert result.ok, result.errors
    assert result.skipped == 0
    assert _count(es, index) == result.indexed
    assert _count(es, index, query={"term": {"@path": "conn"}}) > 0
    hit = es.search(index=index, query={"term": {"@path": "rdp"}}, size=1)["hits"]["hits"][0][
        "_source"
    ]
    assert hit["case"] == "it"
    assert hit["@timestamp"].startswith("20")
    mapping = es.indices.get_mapping(index=index)[index]["mappings"]["properties"]
    assert mapping["@timestamp"]["type"] == "date"
    assert mapping["id"]["properties"]["orig_h"]["type"] == "ip"
    # ip-typed field supports CIDR queries (some records carry IPv6 link-local addresses)
    with_ip = _count(es, index, query={"exists": {"field": "id.orig_h"}})
    v4 = _count(es, index, query={"term": {"id.orig_h": "0.0.0.0/0"}})
    v6 = _count(es, index, query={"term": {"id.orig_h": "::/0"}})
    assert 0 < v4 <= with_ip
    assert v6 == with_ip  # ::/0 covers IPv4-mapped addresses too, so it matches everything


def test_json_and_tsv_logs_land_identically(es, index, data_dir):
    ensure_index(es, index)
    tsv = ZeekToElk(es, index=index, metadata={"fmt": "tsv"}).load(
        str(data_dir / "rdp_sharprdp" / "tsv" / "conn.log")
    )
    js = ZeekToElk(es, index=index, metadata={"fmt": "json"}).load(
        str(data_dir / "rdp_sharprdp" / "json" / "conn.log")
    )
    assert tsv.ok and js.ok
    assert tsv.indexed == js.indexed
    assert _count(es, index, query={"term": {"fmt": "json"}}) == js.indexed


def test_legacy_conn_log_dynamic_mapping(es, index, data_dir):
    result = ZeekToElk(es, index=index).load(str(data_dir / "conn_2018.log"))
    assert result.ok, result.errors
    assert result.indexed == 2164
    assert _count(es, index) == 2164


def test_legacy_batch_to_elk(es, es_url, index, data_dir):
    from urllib.parse import urlsplit

    parts = urlsplit(es_url)
    result = ParseZeekLogs.batch_to_elk(
        str(data_dir / "rdp_sharprdp" / "tsv" / "rdp.log"),
        elk_ip=f"{parts.hostname}:{parts.port or 9200}",
        index=index,
        meta={"legacy": True},
    )
    assert result.ok and result.indexed > 0
    assert _count(es, index, query={"term": {"legacy": True}}) == result.indexed


def test_cli_end_to_end(es, es_url, index, data_dir):
    rc = main(
        [
            "elk",
            str(data_dir / "rdp_sharprdp" / "tsv" / "conn.log"),
            str(data_dir / "c2_dns_txt" / "tsv" / "dns.log"),
            es_url,
            "-i",
            index,
            "--create-index",
            "-m",
            '{"source": "cli"}',
        ]
    )
    assert rc == 0
    assert _count(es, index, query={"term": {"@path": "dns"}}) > 0
    assert _count(es, index, query={"term": {"source": "cli"}}) == _count(es, index)


def test_ecs_documents_index_and_query(es, index, data_dir):
    assert ensure_index(es, index, ecs=True)
    paths = sorted(str(p) for p in (data_dir / "rdp_sharprdp" / "tsv").glob("*.log"))
    result = ZeekToElk(es, index=index, ecs=True, metadata={"observer.name": "lab"}).load_many(
        paths
    )
    assert result.ok, result.errors
    assert _count(es, index) == result.indexed
    conn = _count(es, index, query={"term": {"event.dataset": "zeek.connection"}})
    assert conn > 0
    # ECS-typed fields behave as their types: ip CIDR, long range, keyword term, date sort
    assert _count(es, index, query={"term": {"source.ip": "192.168.0.0/16"}}) > 0
    assert _count(es, index, query={"range": {"event.duration": {"gt": 0}}}) > 0
    assert _count(es, index, query={"exists": {"field": "network.community_id"}}) >= conn
    hit = es.search(
        index=index,
        query={"term": {"event.dataset": "zeek.connection"}},
        sort=[{"@timestamp": "asc"}],
        size=1,
    )["hits"]["hits"][0]["_source"]
    assert hit["ecs"]["version"] and hit["observer"]["name"] == "lab"
    assert isinstance(hit["source"]["port"], int) and isinstance(hit["event"]["duration"], int)
    mapping = es.indices.get_mapping(index=index)[index]["mappings"]["properties"]
    assert mapping["event"]["properties"]["duration"]["type"] == "long"
    assert mapping["zeek"]["properties"]["connection"]["properties"]["state"]["type"] == "keyword"


def test_cli_ecs_end_to_end(es, es_url, index, data_dir):
    rc = main(
        [
            "elk",
            str(data_dir / "rdp_sharprdp" / "tsv" / "dns.log"),
            es_url,
            "-i",
            index,
            "--create-index",
            "--ecs",
        ]
    )
    assert rc == 0
    assert _count(es, index, query={"term": {"event.dataset": "zeek.dns"}}) == _count(es, index)
    assert _count(es, index, query={"exists": {"field": "dns.question.name"}}) > 0
