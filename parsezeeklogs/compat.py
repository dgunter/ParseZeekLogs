"""The 2.x ``ParseZeekLogs`` interface, implemented on top of :class:`ZeekLog`.

Kept so existing scripts keep working::

    for line in ParseZeekLogs("conn.log", output_format="json", safe_headers=True):
        if line is not None:
            out.write(line + "\\n")

Differences from 2.x that were bugs: booleans are real booleans, ``time`` and
``int`` fields are numbers, sets and vectors are lists, and CSV rows keep
their column alignment when a value is unset. Unset values are omitted from
JSON output and written as empty cells in CSV output.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Iterator
from typing import Any

from parsezeeklogs.reader import ZeekLog, to_json


class ParseZeekLogs:
    """Iterate a Zeek log, yielding JSON strings, CSV rows or dicts.

    ``output_format`` is ``"json"``, ``"csv"`` or ``None`` (dicts). ``fields``
    limits the columns, ``safe_headers`` rewrites dots to underscores,
    ``meta`` is merged into every record, ``ignore_keys`` are dropped.
    """

    def __init__(
        self,
        filepath: str,
        batchsize: int = 500,
        fields: Iterable[str] | None = None,
        output_format: str | None = None,
        ignore_keys: Iterable[str] | None = None,
        meta: dict[str, Any] | None = None,
        safe_headers: bool = False,
    ) -> None:
        self.filepath = filepath
        self.batchsize = batchsize
        self.output_format = output_format
        self.ignore_keys = set(ignore_keys or ())
        self.meta = dict(meta) if meta else {}
        self.safe_headers = safe_headers
        self._log = ZeekLog(filepath, fields=fields, safe_headers=safe_headers)
        self._records = self._log.records()
        self.fields = [f for f in self._log.fields if f not in self.ignore_keys]
        self.options = dict(self._log.header.directives) if self._log.header else {}
        self.data_types = {k: v for k, v in self._log.types.items() if k not in self.ignore_keys}

    def __iter__(self) -> Iterator[Any]:
        return self

    def __next__(self) -> Any:
        record = next(self._records)
        for key in self.ignore_keys:
            record.pop(key, None)
        if self.output_format == "json":
            record.update(self.meta)
            return to_json({k: v for k, v in record.items() if v is not None})
        if self.output_format == "csv":
            return self._csv_row(record)
        return record

    def _csv_row(self, record: dict[str, Any]) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_NONNUMERIC, lineterminator="")
        row = []
        for key in self.fields:
            value = record.get(key)
            if value is None:
                row.append("")
            elif isinstance(value, list):
                row.append(",".join("" if v is None else str(v) for v in value))
            elif isinstance(value, bool):
                row.append("T" if value else "F")
            else:
                row.append(value)
        writer.writerow(row)
        return buf.getvalue()

    def get_fields(self) -> str | list[str]:
        """Field names: a comma-joined string for CSV output, otherwise a list."""
        if self.output_format == "csv":
            return ",".join(self.fields)
        return list(self.fields)

    def close(self) -> None:
        self._log.close()

    def __enter__(self) -> ParseZeekLogs:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- 2.x Elasticsearch helpers --------------------------------------------------

    @staticmethod
    def bulk_to_elasticsearch(es: Any, bulk_queue: list[dict[str, Any]]) -> bool:
        from parsezeeklogs.elastic import _require_elasticsearch

        _require_elasticsearch()
        from elasticsearch import helpers

        try:
            helpers.bulk(es, bulk_queue)
        except Exception:  # noqa: BLE001 - 2.x contract: report failure as False
            return False
        return True

    @staticmethod
    def batch_to_elk(
        filepath: str,
        batch_size: int = 500,
        fields: Iterable[str] | None = None,
        elk_ip: str = "127.0.0.1",
        index: str = "zeeklogs",
        meta: dict[str, Any] | None = None,
        ignore_keys: Iterable[str] | None = None,
    ) -> Any:
        """2.x entry point; returns a :class:`~parsezeeklogs.elastic.LoadResult`."""
        from parsezeeklogs.elastic import ZeekToElk, make_client

        del ignore_keys  # accepted for signature compatibility; use ``fields`` instead
        loader = ZeekToElk(
            make_client(elk_ip), index=index, bulk_size=batch_size, metadata=meta, fields=fields
        )
        return loader.load(filepath)


__all__ = ["ParseZeekLogs"]
