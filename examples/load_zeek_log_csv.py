"""Print conn.log as CSV using the 2.x-compatible ParseZeekLogs iterator."""

from parsezeeklogs import ParseZeekLogs

log_iterator = ParseZeekLogs("conn.log", output_format="csv", safe_headers=True)
print(log_iterator.get_fields())
for row in log_iterator:
    print(row)
