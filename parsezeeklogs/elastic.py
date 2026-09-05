"""Bulk-load Zeek records into Elasticsearch. Requires ``parsezeeklogs[elasticsearch]``."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from parsezeeklogs.reader import ZeekLog

if TYPE_CHECKING:
    from elasticsearch import Elasticsearch

log = logging.getLogger(__name__)

DEFAULT_INDEX = "zeeklogs"
TIMESTAMP = "@timestamp"
DEFAULT_BULK_SIZE = 500
DEFAULT_PORT = 9200

#: Mapping applied by ``ensure_index``. Dynamic detection is off so a value that
#: happens to look like a date or a number in one record does not lock the field
#: to that type for every later record.
INDEX_BODY: dict[str, Any] = {
    "mappings": {
        "date_detection": False,
        "numeric_detection": False,
        "properties": {
            TIMESTAMP: {"type": "date"},
            "@path": {"type": "keyword"},
            "ts": {"type": "double"},
            "uid": {"type": "keyword"},
            "id": {
                "properties": {
                    "orig_h": {"type": "ip"},
                    "orig_p": {"type": "integer"},
                    "resp_h": {"type": "ip"},
                    "resp_p": {"type": "integer"},
                }
            },
        },
    }
}


def _require_elasticsearch() -> Any:
    try:
        import elasticsearch
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "Elasticsearch support needs the optional dependency: "
            "pip install 'parsezeeklogs[elasticsearch]'"
        ) from exc
    return elasticsearch


def normalize_url(host: str) -> str:
    """``localhost`` -> ``http://localhost:9200``; URLs with a scheme pass through."""
    host = host.strip()
    if "://" not in host:
        # Plain HTTP is what a bare host has always meant here and what a dev
        # cluster with security disabled speaks; pass https:// for anything else.
        host = f"http://{host}"  # NOSONAR python:S5332 - explicit scheme wins
    parts = urlsplit(host)
    if parts.port is None and parts.scheme == "http":
        netloc = f"{parts.hostname}:{DEFAULT_PORT}"
        if parts.username:
            auth = parts.username
            if parts.password is not None:
                auth = f"{auth}:{parts.password}"
            netloc = f"{auth}@{netloc}"
        host = parts._replace(netloc=netloc).geturl()
    return host


def make_client(
    url: str,
    *,
    user: str | None = None,
    password: str | None = None,
    api_key: str | None = None,
    ca_certs: str | None = None,
    verify_certs: bool = True,
    timeout: float = 60,
) -> Elasticsearch:
    """Build an ``Elasticsearch`` client from CLI-style options."""
    elasticsearch = _require_elasticsearch()
    kwargs: dict[str, Any] = {"request_timeout": timeout}
    if user is not None:
        kwargs["basic_auth"] = (user, password or "")
    if api_key is not None:
        kwargs["api_key"] = api_key
    if ca_certs is not None:
        kwargs["ca_certs"] = ca_certs
    if not verify_certs:
        kwargs["verify_certs"] = False
        kwargs["ssl_show_warn"] = False
    return elasticsearch.Elasticsearch(normalize_url(url), **kwargs)


def ensure_index(es: Elasticsearch, index: str, ecs: bool = False) -> bool:
    """Create ``index`` with the recommended mapping if missing. Returns True if created.

    With ``ecs=True`` the mapping is generated from the ECS/Beats field table so it
    matches the documents :func:`parsezeeklogs.ecs.to_ecs` produces.
    """
    if es.indices.exists(index=index):
        return False
    if ecs:
        from parsezeeklogs.ecs import ecs_index_body

        es.indices.create(index=index, **ecs_index_body())
    else:
        es.indices.create(index=index, **INDEX_BODY)
    return True


def to_document(record: dict[str, Any], path: str | None = None) -> dict[str, Any]:
    """Add ``@timestamp`` (from ``ts``) and ``@path`` to a record for indexing."""
    doc = dict(record)
    ts = doc.get("ts")
    if isinstance(ts, (int, float)):
        doc[TIMESTAMP] = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    elif isinstance(ts, datetime):
        doc[TIMESTAMP] = ts.isoformat()
        doc["ts"] = ts.timestamp()
    elif isinstance(ts, str):
        doc[TIMESTAMP] = ts
    if path:
        doc["@path"] = path
    return doc


@dataclass
class LoadResult:
    """Outcome of loading one or more files."""

    indexed: int = 0
    failed: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.failed == 0

    def add(self, other: LoadResult, max_errors: int) -> None:
        self.indexed += other.indexed
        self.failed += other.failed
        self.skipped += other.skipped
        self.errors.extend(other.errors[: max(0, max_errors - len(self.errors))])


class ZeekToElk:
    """Stream Zeek log files into an Elasticsearch index."""

    def __init__(
        self,
        es: Elasticsearch,
        index: str = DEFAULT_INDEX,
        bulk_size: int = DEFAULT_BULK_SIZE,
        metadata: dict[str, Any] | None = None,
        fields: Iterable[str] | None = None,
        max_error_samples: int = 10,
        ecs: bool = False,
    ) -> None:
        self.es = es
        self.index = index
        self.bulk_size = max(1, int(bulk_size))
        self.metadata = dict(metadata) if metadata else None
        self.fields = list(fields) if fields is not None else None
        self.max_error_samples = max_error_samples
        self.ecs = ecs

    def actions(self, path: str, result: LoadResult | None = None) -> Iterator[dict[str, Any]]:
        """Yield bulk actions for ``path``; unreadable lines are counted on ``result``."""
        result = result if result is not None else LoadResult()

        def on_error(_line: int, _text: str, _exc: Exception) -> None:
            result.skipped += 1

        if self.ecs:
            from parsezeeklogs.ecs import to_ecs

            def build(record: dict[str, Any], log_path: str | None) -> dict[str, Any]:
                return to_ecs(record, log_path, self.metadata)

            meta = None
        else:
            build, meta = to_document, self.metadata

        with ZeekLog(path, fields=self.fields, meta=meta, on_error=on_error) as zeek_log:
            log_path = zeek_log.path
            for record in zeek_log:
                yield {"_index": self.index, "_source": build(record, log_path)}

    def load(self, path: str) -> LoadResult:
        """Index every readable record of ``path`` and return counts."""
        _require_elasticsearch()
        from elasticsearch import helpers

        result = LoadResult()
        stream = helpers.streaming_bulk(
            self.es,
            self.actions(path, result),
            chunk_size=self.bulk_size,
            raise_on_error=False,
            max_retries=3,
        )
        for ok, item in stream:
            if ok:
                result.indexed += 1
            else:
                result.failed += 1
                if len(result.errors) < self.max_error_samples:
                    result.errors.append(str(item))
        log.info(
            "%s: indexed=%d failed=%d skipped=%d",
            path,
            result.indexed,
            result.failed,
            result.skipped,
        )
        return result

    def load_many(self, paths: Iterable[str]) -> LoadResult:
        total = LoadResult()
        for path in paths:
            total.add(self.load(path), self.max_error_samples)
        return total


__all__ = [
    "INDEX_BODY",
    "LoadResult",
    "ZeekToElk",
    "ensure_index",
    "make_client",
    "normalize_url",
    "to_document",
]
