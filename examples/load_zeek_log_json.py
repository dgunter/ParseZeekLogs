"""Print each conn.log record as a JSON object."""

from parsezeeklogs import read_zeek, to_json

for record in read_zeek("conn.log"):
    print(to_json(record))
