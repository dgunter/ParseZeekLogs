ParseBroLogs
============

A lightweight utility for programmatically reading and manipulating Bro
IDS log files and outputting into JSON or CSV format. This library works
on both Python 2 and Python 3.

Examples
--------

The following example first loads records from the Bro connection log
named conn.log. The data is the written out to a file named out.json.
The name of the log file to read must be provided when creating the
ParseBroLog class.

.. code:: python

    from parsebrologs import ParseBroLogs

    log_data = ParseBroLogs("conn.log")
    with open('out.json',"w") as outfile:
        outfile.write(log_data.to_json())

This is another example that instead uses the to_csv method to write the
data out to a file named out.csv. This example shows filtering on
specific fields within the log file. Field names should be provided as
list elements.

.. code:: python

    from parsebrologs import ParseBroLogs

    log_data = ParseBroLogs("conn.log", fields=["ts", "id.orig_h", "id.resp_h"])
    with open('out.csv',"w") as outfile:
        outfile.write(log_data.to_csv())

If you are planning to open the csv using Microsoft Excel or OpenOffice,
you might want to use the to_escaped_csv() method. This adds quotes
around the data escaping any commas or other special characters that
cause problems with csv viewers.

.. code:: python

    from parsebrologs import ParseBroLogs

    log_data = ParseBroLogs("conn.log"])
    with open('out.csv','w') as outfile:
        outfile.write(log_data.to_escaped_csv())

If you are planning on using pandas to manipulate the data, you can use
the to_raw_data method directly with Pandas constructor. Because the
to_json() method returns the json data as a string, you should use the
json library to convert out of string format.

.. code:: python

    from parsebrologs import ParseBroLogs
    import pandas as pd
    import json

    log_data = ParseBroLogs("conn.log", fields=["ts", "id.orig_h", "id.resp_h"])
    df = pd.DataFrame(json.loads(log_data.to_json()))
    df