"""Bulk-load http.log into Elasticsearch (pip install 'parsezeeklogs[elasticsearch]')."""

from parsezeeklogs.elastic import ZeekToElk, ensure_index, make_client

es = make_client("http://localhost:9200")
ensure_index(es, "zeeklogs")
result = ZeekToElk(es, index="zeeklogs", metadata={"source": "http"}).load("http.log")
print(f"indexed={result.indexed} failed={result.failed} skipped={result.skipped}")
