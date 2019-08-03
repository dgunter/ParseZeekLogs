from parsezeeklogs import ParseZeekLogs

with open('out.csv',"w") as outfile:
    for log_record in ParseZeekLogs("conn.log", output_format="csv", safe_headers=False, fields=["ts","id.orig_h","id.orig_p","id.resp_h","id.resp_p"]):
        if log_record is not None:
            outfile.write(log_record + "\n")
