from parsebrologs import ParseBroLogs

log_data = ParseBroLogs("conn.log", fields=["ts", "id.orig_h", "id.resp_h"])
with open('out.csv','w') as outfile:
    outfile.write(log_data.to_escaped_csv())