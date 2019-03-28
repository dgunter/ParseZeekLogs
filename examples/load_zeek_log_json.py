from parsezeeklogs import ParseZeekLogs

# Print the field line out
for log_record in ParseZeekLogs("conn.log", output_format="json", safe_headers=False):
    if log_record is not None:
        print(str(log_record))
