"""Work with typed records directly: long connections to non-local hosts."""

from parsezeeklogs import ZeekLog

with ZeekLog("conn.log", time_format="iso") as log:
    print(log.path, log.types["duration"])  # conn interval
    for rec in log:
        if rec["duration"] is not None and rec["duration"] > 60 and rec["local_resp"] is False:
            print(rec["ts"], rec["id.orig_h"], "->", rec["id.resp_h"], rec["duration"])
