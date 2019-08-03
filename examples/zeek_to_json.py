#!/usr/bin/env python3

# File: zeek_to_json.py
# Description: Convert multiple bro files to json
#
# Usage: 
#   ./zeek_to_json.py *.log
#  ^^ will convert all zeek logs in this directory to same filename + .json (example: conn.log -> conn.json)

from parsezeeklogs import ParseZeekLogs
import argparse
import os

if __name__ == "__main__":
    # Create argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('zeekfile',  nargs='+', help="Zeek file file to parse")

    # Parse arguments 
    args = parser.parse_args()

    # Loop through each Bro file and convert to json
    for zeek_file in args.zeekfile:
        outfilename = os.path.splitext(zeek_file)[0] + '.json'

        #log_data = ParseBroLogs(bro_file)
        with open(outfilename, "w") as outfile:
            for log_data in ParseZeekLogs(zeek_file, output_format="json"):
                outfile.write(log_data)
