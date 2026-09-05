"""parsezeeklogs: read Zeek (Bro) logs into typed Python records.

    from parsezeeklogs import read_zeek

    for record in read_zeek("conn.log"):
        print(record["id.orig_h"], record["id.resp_p"], record["duration"])

Both the TSV and JSON log formats are supported. See :class:`ZeekLog` for the
options, :mod:`parsezeeklogs.elastic` for the Elasticsearch loader (install
``parsezeeklogs[elasticsearch]``), and :class:`ParseZeekLogs` for the 2.x API.
"""

from parsezeeklogs.compat import ParseZeekLogs
from parsezeeklogs.ecs import to_ecs
from parsezeeklogs.reader import (
    ZeekHeader,
    ZeekLog,
    decode_escapes,
    read_zeek,
    safe_name,
    to_json,
    write_csv,
    write_json_lines,
)

__version__ = "3.0.0"

__all__ = [
    "ParseZeekLogs",
    "ZeekHeader",
    "ZeekLog",
    "__version__",
    "decode_escapes",
    "read_zeek",
    "safe_name",
    "to_ecs",
    "to_json",
    "write_csv",
    "write_json_lines",
]
