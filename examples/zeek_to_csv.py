"""Write selected conn.log columns to out.csv (CLI: parsezeeklogs csv conn.log -f ...)."""

from parsezeeklogs import read_zeek, write_csv

FIELDS = ["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"]

with open("out.csv", "w", encoding="utf-8", newline="") as out:
    write_csv(read_zeek("conn.log", fields=FIELDS), out, FIELDS)
