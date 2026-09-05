"""Read Zeek logs, in TSV (``LogAscii`` default) or JSON form, into typed dicts.

Zeek's TSV writer describes each file in ``#`` header lines: the separators, the
markers for unset (``-``) and empty (``(empty)``) values, the field names and
their Zeek types. This module honours all of them:

* ``count``, ``int``, ``port`` -> ``int``; ``double``, ``interval``, ``time`` -> ``float``
* ``bool`` -> ``bool`` (Zeek writes ``T``/``F``)
* ``set[...]``, ``vector[...]`` -> ``list`` of the converted element type
* every other type (``string``, ``addr``, ``subnet``, ``enum``, ...) -> ``str``
  with Zeek's ``\\xHH`` byte escapes decoded
* unset -> ``None``, empty -> ``""`` or ``[]``

JSON logs (``LogAscii::use_json=T``) are already typed by Zeek and are passed
through, so the same call site can read either form.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import IO, Any, Literal

log = logging.getLogger(__name__)

TimeFormat = Literal["epoch", "iso", "datetime"]
ErrorHook = Callable[[int, str, Exception], None]

_CONTAINER = re.compile(r"^(set|vector|table)\[(.+)\]$")
_ESCAPE = re.compile(rb"\\(x[0-9a-fA-F]{2}|\\)")
_INT_TYPES = frozenset({"count", "int", "port"})
_FLOAT_TYPES = frozenset({"double", "interval"})


def _unescape_match(match: re.Match[bytes]) -> bytes:
    body = match.group(1)
    if body == b"\\":
        return b"\\"
    return bytes([int(body[1:], 16)])


def decode_escapes(value: str) -> str:
    """Undo the escaping Zeek's ASCII writer applies to string values.

    Separators, non-printable bytes and the ``(empty)``/``-`` markers are written
    as ``\\xHH``; a literal backslash is written as ``\\\\``. Both are decoded in
    one left-to-right pass so ``\\\\x01`` stays the two characters ``\\x01`` as
    Zeek's JSON writer also renders it.
    """
    if "\\" not in value:
        return value
    raw = _ESCAPE.sub(_unescape_match, value.encode("utf-8"))
    return raw.decode("utf-8", errors="replace")


def _unescape_directive(value: str) -> str:
    """Header directive values (e.g. ``#separator \\x09``) use the same escaping."""
    return decode_escapes(value)


@dataclass
class ZeekHeader:
    """The ``#`` directives at the top of a TSV Zeek log."""

    separator: str = "\t"
    set_separator: str = ","
    empty_field: str = "(empty)"
    unset_field: str = "-"
    path: str | None = None
    fields: list[str] = field(default_factory=list)
    types: list[str] = field(default_factory=list)
    directives: dict[str, str] = field(default_factory=dict)

    def apply(self, line: str) -> None:
        """Absorb one ``#directive value`` line."""
        body = line[1:]
        if body.startswith("separator "):
            self.separator = _unescape_directive(body.split(" ", 1)[1].strip())
            self.directives["separator"] = self.separator
            return
        key, _, rest = body.partition(self.separator)
        key = key.strip()
        if key == "set_separator":
            self.set_separator = rest
        elif key == "empty_field":
            self.empty_field = rest
        elif key == "unset_field":
            self.unset_field = rest
        elif key == "path":
            self.path = rest
        elif key == "fields":
            self.fields = rest.split(self.separator) if rest else []
        elif key == "types":
            self.types = rest.split(self.separator) if rest else []
        self.directives[key] = rest


def _format_time(value: float, time_format: TimeFormat) -> Any:
    if time_format == "epoch":
        return value
    stamp = datetime.fromtimestamp(value, tz=timezone.utc)
    return stamp if time_format == "datetime" else stamp.isoformat()


def convert_scalar(value: str, ztype: str, header: ZeekHeader, time_format: TimeFormat) -> Any:
    """Convert one TSV cell of a scalar Zeek type."""
    if value == header.unset_field:
        return None
    if ztype in _INT_TYPES:
        return int(value)
    if ztype in _FLOAT_TYPES:
        return float(value)
    if ztype == "time":
        return _format_time(float(value), time_format)
    if ztype == "bool":
        return value == "T"
    if value == header.empty_field:
        return ""
    return decode_escapes(value)


def convert_value(value: str, ztype: str, header: ZeekHeader, time_format: TimeFormat) -> Any:
    """Convert one TSV cell, handling ``set[...]``/``vector[...]`` containers."""
    container = _CONTAINER.match(ztype)
    if container is None:
        return convert_scalar(value, ztype, header, time_format)
    if value == header.unset_field:
        return None
    if value == header.empty_field:
        return []
    inner = container.group(2)
    return [
        convert_scalar(item, inner, header, time_format)
        for item in value.split(header.set_separator)
    ]


def safe_name(name: str) -> str:
    """``id.orig_h`` -> ``id_orig_h`` (dots are object separators in Elasticsearch)."""
    return name.replace(".", "_")


def _open_source(source: str | os.PathLike[str] | IO[str]) -> tuple[IO[str], bool]:
    """Return a text handle and whether we own it (and must close it)."""
    if isinstance(source, (str, os.PathLike)):
        path = os.fspath(source)
        if path.endswith(".gz"):
            return gzip.open(path, "rt", encoding="utf-8", errors="replace", newline=""), True
        return open(path, encoding="utf-8", errors="replace", newline=""), True
    return source, False


class ZeekLog:
    """Iterate the records of one Zeek log file as dicts.

    ``source`` is a path (``.gz`` is transparent) or an open text handle. The
    format is detected from the first line: ``#`` starts a TSV header, ``{`` a
    JSON log. Use it as a context manager or iterate it once; ``fields`` limits
    the keys returned, ``safe_headers`` rewrites dots to underscores,
    ``time_format`` controls how ``time`` values come back, and ``meta`` is
    merged into every record.
    """

    def __init__(
        self,
        source: str | os.PathLike[str] | IO[str],
        *,
        fields: Iterable[str] | None = None,
        safe_headers: bool = False,
        time_format: TimeFormat = "epoch",
        meta: dict[str, Any] | None = None,
        on_error: ErrorHook | None = None,
    ) -> None:
        self._fh, self._owns_fh = _open_source(source)
        self.name = os.fspath(source) if isinstance(source, (str, os.PathLike)) else None
        self.wanted = set(fields) if fields is not None else None
        self.safe_headers = safe_headers
        self.time_format = time_format
        self.meta = dict(meta) if meta else None
        self.on_error = on_error
        self.header: ZeekHeader | None = None
        self.is_json = False
        self.line_number = 0
        self.skipped = 0
        self._pending: str | None = None
        self._read_preamble()

    # -- setup -------------------------------------------------------------------

    def _read_preamble(self) -> None:
        line = self._fh.readline()
        while line and not line.strip():
            line = self._fh.readline()
        self.line_number += 1
        if line.lstrip().startswith("{"):
            self.is_json = True
            self._pending = line
            return
        self.header = ZeekHeader()
        while line.startswith("#"):
            self.header.apply(line.rstrip("\r\n"))
            line = self._fh.readline()
            self.line_number += 1
        self._pending = line
        if not self.header.fields:
            raise ValueError(
                f"{self.name or 'stream'}: no #fields header found; not a Zeek TSV log"
            )
        if len(self.header.types) != len(self.header.fields):
            raise ValueError(f"{self.name or 'stream'}: #fields and #types disagree in length")

    @property
    def path(self) -> str | None:
        """The Zeek log path (``conn``, ``dns``, ...) from ``#path`` or the file name."""
        if self.header and self.header.path:
            return self.header.path
        if self.name:
            base = os.path.basename(self.name)
            for suffix in (".gz", ".log", ".json"):
                if base.endswith(suffix):
                    base = base[: -len(suffix)]
            return base or None
        return None

    @property
    def fields(self) -> list[str]:
        """Field names as they appear in returned records, after filtering and renaming."""
        if self.header is None:
            return []
        names = [safe_name(f) if self.safe_headers else f for f in self.header.fields]
        if self.wanted is None:
            return names
        return [n for n, raw in zip(names, self.header.fields, strict=True) if self._want(n, raw)]

    @property
    def types(self) -> dict[str, str]:
        """Zeek type per returned field (empty for JSON logs, which carry no header)."""
        if self.header is None:
            return {}
        out = {}
        for raw, ztype in zip(self.header.fields, self.header.types, strict=True):
            name = safe_name(raw) if self.safe_headers else raw
            if self._want(name, raw):
                out[name] = ztype
        return out

    def _want(self, name: str, raw: str) -> bool:
        return self.wanted is None or name in self.wanted or raw in self.wanted

    # -- iteration ---------------------------------------------------------------

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return self.records()

    def __enter__(self) -> ZeekLog:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_fh:
            self._fh.close()

    def _lines(self) -> Iterator[str]:
        if self._pending is not None:
            pending, self._pending = self._pending, None
            if pending:
                yield pending
        for line in self._fh:
            self.line_number += 1
            yield line

    def _report(self, line: str, exc: Exception) -> None:
        self.skipped += 1
        log.warning("%s line %d skipped: %s", self.name or "stream", self.line_number, exc)
        if self.on_error:
            self.on_error(self.line_number, line, exc)

    def records(self) -> Iterator[dict[str, Any]]:
        """Yield one dict per record. Malformed lines are reported and skipped."""
        for raw in self._lines():
            line = raw.rstrip("\r\n")
            if not line:
                continue
            if self.is_json:
                record = self._json_record(line)
            elif line.startswith("#"):
                # Concatenated/rotated logs repeat their header block mid-stream.
                assert self.header is not None
                self.header.apply(line)
                continue
            else:
                record = self._tsv_record(line)
            if record is None:
                continue
            if self.meta:
                record.update(self.meta)
            yield record

    def _json_record(self, line: str) -> dict[str, Any] | None:
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            self._report(line, exc)
            return None
        if not isinstance(record, dict):
            self._report(line, ValueError("JSON line is not an object"))
            return None
        if self.safe_headers:
            record = {safe_name(k): v for k, v in record.items()}
        if self.wanted is not None:
            record = {k: v for k, v in record.items() if k in self.wanted}
        if self.time_format != "epoch" and isinstance(record.get("ts"), (int, float)):
            record["ts"] = _format_time(float(record["ts"]), self.time_format)
        return record

    def _tsv_record(self, line: str) -> dict[str, Any] | None:
        header = self.header
        assert header is not None
        cells = line.split(header.separator)
        if len(cells) != len(header.fields):
            self._report(
                line,
                ValueError(f"expected {len(header.fields)} columns, found {len(cells)}"),
            )
            return None
        record: dict[str, Any] = {}
        try:
            for raw_name, ztype, cell in zip(header.fields, header.types, cells, strict=True):
                name = safe_name(raw_name) if self.safe_headers else raw_name
                if not self._want(name, raw_name):
                    continue
                record[name] = convert_value(cell, ztype, header, self.time_format)
        except ValueError as exc:
            self._report(line, exc)
            return None
        return record


def read_zeek(source: str | os.PathLike[str] | IO[str], **options: Any) -> Iterator[dict[str, Any]]:
    """Iterate the records of ``source`` and close it afterwards. Options as for ``ZeekLog``."""
    with ZeekLog(source, **options) as zeek_log:
        yield from zeek_log


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"not JSON serialisable: {type(value).__name__}")


def to_json(record: dict[str, Any], **kwargs: Any) -> str:
    """Serialise one record as a JSON object (datetimes as ISO-8601)."""
    kwargs.setdefault("default", _json_default)
    return json.dumps(record, **kwargs)


def write_json_lines(records: Iterable[dict[str, Any]], out: IO[str]) -> int:
    """Write records as JSON lines; returns the count."""
    count = 0
    for record in records:
        out.write(to_json(record))
        out.write("\n")
        count += 1
    return count


def _csv_cell(value: Any, list_separator: str) -> Any:
    if value is None:
        return ""
    if isinstance(value, list):
        return list_separator.join("" if v is None else str(v) for v in value)
    if isinstance(value, bool):
        return "T" if value else "F"
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def write_csv(
    records: Iterable[dict[str, Any]],
    out: IO[str],
    fields: list[str] | None = None,
    *,
    header: bool = True,
    list_separator: str = ",",
) -> int:
    """Write records as CSV; returns the count.

    ``fields`` fixes the column order (default: the keys of the first record).
    ``None`` becomes an empty cell, lists are joined with ``list_separator``.
    """
    import csv

    columns = list(fields) if fields is not None else None
    writer: csv.DictWriter | None = None
    count = 0
    for record in records:
        if writer is None:
            columns = columns if columns is not None else list(record)
            writer = csv.DictWriter(
                out, fieldnames=columns, extrasaction="ignore", lineterminator="\n"
            )
            if header:
                writer.writeheader()
        writer.writerow({key: _csv_cell(record.get(key), list_separator) for key in columns or ()})
        count += 1
    if writer is None and header and columns:
        csv.DictWriter(out, fieldnames=columns, lineterminator="\n").writeheader()
    return count


__all__ = [
    "ZeekHeader",
    "ZeekLog",
    "convert_scalar",
    "convert_value",
    "decode_escapes",
    "read_zeek",
    "safe_name",
    "to_json",
    "write_csv",
    "write_json_lines",
]
