import json
from collections import OrderedDict


class ParseBroLogs(object):
    """Class that parses Bro logs and allows log data to be output in CSV or json format.

    Attributes:
        filepath: Path of Bro log file to read

    """

    def __init__(self, filepath, fields=None):
        """ Initializes class with data from file with provided filename """
        self.data = self._read_log(filepath, fields)

    def _read_log(self, filepath, fields=None):
        """ Reads data from a bro log file """
        options = OrderedDict()
        self.filtered_fields = fields
        options['data'] = []
        options['separator'] = "\t"  # Set a default separator in case we don't get the separator
        with open(filepath) as infile:
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
                            if fields is None or options.get("fields")[x] in self.filtered_fields:
                                record[options.get("fields")[x]] = data[x]
                        options["data"].append(record)
                    else:
                        # Arrays are not the same length
                        pass
        self.fields = options.get("fields")
        return options

    def get_filtered_fields(self):
        """Returns all log fields with the field filter applied

        Returns:
            A python list containing the field names in string format with the field filter applied
        """
        return self.filtered_fields

    def get_fields(self):
        """Returns all fields present in the log file

        Returns:
            A python list containing all field names in the log file
        """
        return self.fields

    def to_csv(self):
        """Returns Bro data in CSV format

        Returns:
            A string in CSV format containing all Bro log data

        """
        csv = ""
        for v in self.data.get("fields"):
            if self.filtered_fields is None or v in self.filtered_fields:
                csv += v + ","
        csv += "\n"
        data_temp = sorted(self.data.get("data"), key=lambda record: record.get("ts"))
        for record in data_temp:
            for v in record.values():
                csv += v + ","
            csv += "\n"
        return csv

    def to_escaped_csv(self):
        """ Returns Bro data in CSV format with escape characters. This allows fields with , to properly display

        Returns:
            A string in CSV format containing all Bro log data. All fields are escaped.

        """
        csv = ""
        for v in self.data.get("fields"):
            if self.filtered_fields is None or v in self.filtered_fields:
                csv += v + ","
        csv += "\n"
        data_temp = sorted(self.data.get("data"), key=lambda record: record.get("ts"))
        for record in data_temp:
            for v in record.values():
                csv += "\"" + v + "\"" + ","
            csv += "\n"
        return csv

    def to_json(self):
        """Returns Bro data as a JSON formatted string

        Returns:
            The log data as a JSON formatted string

        """
        return json.dumps(self.data.get('data'))

    def __str__(self):
        return json.dumps(self.data)
