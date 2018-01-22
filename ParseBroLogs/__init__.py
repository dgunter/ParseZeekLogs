import json
from collections import OrderedDict


class ParseBroLogs(object):
    """Class that parses Bro logs and allows log data to be output in CSV or json format.

    Attributes:
        filepath: Path of Bro log file to read

    """

    def __init__(self, filepath):
        """ Initializes class with data from file with provided filename """
        self.data = self._read_log(filepath)

    def _read_log(self, filename):
        """ Reads data from a bro log file """
        options = OrderedDict()
        options['data'] = []
        options['separator'] = "\t"  # Set a default separator in case we don't get the separator
        with open(filename) as infile:
            for line in infile.readlines():
                if line.startswith("#separator"):
                    key = str(line[1:].split(" ")[0])
                    value = str.encode(line[1:].split(" ")[1].strip()).decode('unicode_escape')
                    options[key] = value
                elif line.startswith("#"):
                    key = str(line[1:].split(options.get('seperator'))[0])
                    value = line[1:].split(options.get('seperator'))[1:]
                    options[key] = value
                else:
                    data = line.split(options.get('seperator'))
                    if len(data) is len(options.get("fields")):
                        record = OrderedDict()
                        for x in range(0, len(data) - 1):
                            record[options.get("fields")[x]] = data[x]
                        options["data"].append(record)
                    else:
                        # Arrays are not the same length
                        pass
            return options

    def to_csv(self):
        """Returns Bro data in CSV format

        Returns:
            A string in CSV format containing all Bro log data

        """
        csv = ""
        for v in self.data.get("fields"):
            csv += v + ","
        csv += "\n"
        data_temp = sorted(self.data.get("data"), key=lambda record: record.get("ts"))
        for record in data_temp:
            for v in record.values():
                csv += v + ","
            csv += "\n"
        return csv

    def to_excel_csv(self):
        """ Returns Bro data in CSV format with escape characters. This allows fields with , to properly display

        Returns:
            A string in CSV format containing all Bro log data. All fields are escaped.

        """
        csv = ""
        for v in self.data.get("fields"):
            csv += v + ","
        csv += "\n"
        data_temp = sorted(self.data.get("data"), key=lambda record: record.get("ts"))
        for record in data_temp:
            for v in record.values():
                csv += "\"" + v + "\"" + ","
            csv += "\n"
        return csv

    def to_json(self):
        """Returns Bro data in JSON format

        Returns:
            A string containing the Bro log data in JSON format.

        """
        return json.dumps(self.data.get('data'))

    def __str__(self):
        return json.dumps(self.data)