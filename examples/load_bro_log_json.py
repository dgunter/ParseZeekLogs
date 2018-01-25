from parsebrologs import ParseBroLogs

log_data = ParseBroLogs("conn.log")
with open('out.json',"w") as outfile:
    outfile.write(log_data.to_json())