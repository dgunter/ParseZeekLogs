#!/usr/bin/env python3
"""Convert Zeek logs to JSON lines: ./zeek_to_json.py *.log  (conn.log -> conn.json).

The same thing is available as ``parsezeeklogs json conn.log -o conn.json``.
"""

import argparse
import os

from parsezeeklogs import read_zeek, write_json_lines

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("zeekfile", nargs="+", help="Zeek log files to convert")
    args = parser.parse_args()
    for zeek_file in args.zeekfile:
        out_name = os.path.splitext(zeek_file)[0] + ".json"
        with open(out_name, "w", encoding="utf-8") as out:
            count = write_json_lines(read_zeek(zeek_file), out)
        print(f"{zeek_file}: {count} records -> {out_name}")
