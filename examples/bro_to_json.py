#!/usr/bin/env python3

# File: bro_to_json.py
# Description: Convert multiple bro files to json
#
# Usage: 
#   ./bro_to_json.py *.log
#  ^^ will convert all bro logs in this directory to same filename + .json (example: conn.log -> conn.json)

from parsebrologs import ParseBroLogs
import argparse
import os

if __name__ == "__main__":
    # Create argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('brofile',  nargs='+', help="Bro file file to parse")

    # Parse arguments 
    args = parser.parse_args()

    # Loop through each Bro file and convert to json
    for bro_file in args.brofile:
        outfilename = os.path.splitext(bro_file)[0] + '.json'

        log_data = ParseBroLogs(bro_file)
        with open(outfilename, "w") as outfile:
            outfile.write(log_data.to_json())       