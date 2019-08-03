# ParseZeekLogs
A lightweight utility for programmatically reading and manipulating Zeek (Bro) NSM log files and outputting into JSON or CSV format. This library works on both Python 2 and Python 3.

## Examples
The following example first loads records from the Zeek connection log named conn.log. The data is the written out to a file named out.json. The name of the log file to read must be provided when creating the ParseBroLog class. You can use the safe_headers=True option in the to_json method to replace all instances of a dot with an underscore.
```python
from parsezeeklogs import ParseZeekLogs

with open('out.json',"w") as outfile:
    for log_record in ParseZeekLogs("conn.log", output_format="json", safe_headers=False):
        if log_record is not None:
            outfile.write(log_record + "\n")
```

This is another example that instead uses the csv output method to write the data out to a file named out.csv. This example shows filtering on specific fields within the log file. Field names should be provided as list elements.

```python
from parsezeeklogs import ParseZeekLogs

with open('out.csv',"w") as outfile:
    for log_record in ParseZeekLogs("conn.log", output_format="csv", safe_headers=False, fields=["ts","id.orig_h","id.orig_p","id.resp_h","id.resp_p"]):
        if log_record is not None:
            outfile.write(log_record + "\n")
```

## Special Thanks
* [@geekscrapy](https://github.com/geekscrapy): For bug fixes and the safe header feature addition
