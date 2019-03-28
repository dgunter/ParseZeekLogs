from parsezeeklogs import ParseZeekLogs

log_iterator = ParseZeekLogs("conn.log", output_format="csv", safe_headers=False)
# Print the field line out
print(log_iterator.get_fields())
for log_record in log_iterator:
    if log_record is not None:
        print(str(log_record))