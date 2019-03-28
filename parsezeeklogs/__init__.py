from json import loads, dumps
from collections import OrderedDict
from elasticsearch import Elasticsearch, helpers
from datetime import datetime
from traceback import print_exc


class ParseZeekLogs(object):
    """Class that parses Zeek logs and allows log data to be output in CSV or json format.

    Attributes:
        filepath: Path of Zeek log file to read

    """

    def __init__(self, filepath, batchsize=500, fields=None, output_format=None, ignore_keys=[], meta={}, safe_headers=False):
        self.fd = open(filepath,"r")
        self.options = OrderedDict()
        self.firstRun = True
        self.filtered_fields = fields
        self.batchsize = batchsize
        self.output_format = output_format
        self.ignore_keys = ignore_keys
        self.meta = meta
        self.safe_headers = safe_headers

        # Convert ' to " in meta string
        meta = loads(dumps(meta).replace("'", '"'))

        # Read the header option lines
        l = self.fd.readline()
        while l.strip().startswith("#"):
            # Parse the options out
            if l.startswith("#separator"):
                key = str(l[1:].split(" ")[0])
                value = str.encode(l[1:].split(" ")[1].strip()).decode('unicode_escape')
                self.options[key] = value
            elif l.startswith("#"):
                key = str(l[1:].split(self.options.get('separator'))[0])
                value = l[1:].split(self.options.get('separator'))[1:]
                self.options[key] = value

            # Read the next line
            l = self.fd.readline()

        self.firstLine = l

        # Save mapping of fields to values:
        self.fields = self.options.get('fields')
        self.types = self.options.get('types')

        # Convert field names if safe_headers is enabled
        #if self.safe_headers is True:
        #    for i, val in enumerate(self.fields):
        #        self.fields[i] = self.fields[i].replace(".", "_")

        self.data_types = {}
        for i, val in enumerate(self.fields):
            # Convert field names if safe_headers is enabled
            if self.safe_headers is True:
                self.fields[i] = self.fields[i].replace(".", "_")

            # Match types with each other
            self.data_types[self.fields[i]] = self.types[i]

    def __del__(self):
        self.fd.close()

    def __iter__(self):
        return self

    def __next__(self):
        retVal = ""
        if self.firstRun is True:
            retVal = self.firstLine
            self.firstRun = False
        else:
            retVal = self.fd.readline()

        # If an empty string is returned, readline is done reading
        if retVal == "" or retVal is None:
            raise StopIteration

        # Split out the data we are going to return
        retVal = retVal.split(self.options.get('separator'))

        record = None
        # Make sure we aren't dealing with a comment line
        if len(retVal) > 0 and not str(retVal[0]).strip().startswith("#") \
                and len(retVal) is len(self.options.get("fields")):
            record = OrderedDict()
            # Prepare fields for conversion
            for x in range(0, len(retVal)):
                if self.safe_headers is True:
                    converted_field_name = self.options.get("fields")[x].replace(".", "_")
                else:
                    converted_field_name = self.options.get("fields")[x]
                if self.filtered_fields is None or converted_field_name in self.filtered_fields:
                    # Translate - to "" to fix a conversation error
                    if retVal[x] == "-":
                        retVal[x] = ""
                    # Save the record field if the field isn't filtered out
                    record[converted_field_name] = retVal[x]

            # Convert values to the appropriate record type
            record = self.convert_values(record, self.ignore_keys, self.data_types)

            if record is not None and self.output_format == "json":
                # Output will be json

                # Add metadata to json
                for k, v in self.meta.items():
                    record[k] = v

                retVal = dumps(record)
            elif record is not None and self.output_format == "csv":
                retVal = ""
                # Add escaping to csv format
                for k, v in record.items():
                    # Add escaping to string values
                    if isinstance(v, str):
                        retVal += str("\"" + str(v).strip() + "\"" + ",")
                    else:
                        retVal += str(str(v).strip() + ",")
                # Remove the trailing comma
                retVal = retVal[:-1]
        else:
            retVal = ""

        return retVal

    def convert_values(self, data, ignore_keys=[], data_types={}):
        keys_to_delete = []
        for k, v in data.items():
            # print("evaluating k: " + str(k) + " v: " + str(v))

            if isinstance(v, dict):
                data[k] = self.convert_values(v)
            else:
                if data_types.get(k) is not None:
                    if (data_types.get(k) == "port" or data_types.get(k) == "count"):
                        if v != "":
                            data[k] = int(v)
                        else:
                            keys_to_delete.append(k)
                    elif (data_types.get(k) == "double" or data_types.get(k) == "interval"):
                        if v != "":
                            data[k] = float(v)
                        else:
                            keys_to_delete.append(k)
                    elif data_types.get(k) == "bool":
                        data[k] = bool(v)
                    else:
                        data[k] = v

        for k in keys_to_delete:
            del data[k]

        return data

    def get_fields(self):
        """Returns all fields present in the log file

        Returns:
            A python list containing all field names in the log file
        """
        field_names = ""
        if self.output_format == "csv":
            for i, v in enumerate(self.fields):
                if self.filtered_fields is None or v in self.filtered_fields:
                    field_names += str(v) + ","
            # Remove the trailing comma
            field_names = field_names[:-1].strip()
        else:
            field_names = []
            for i, v in enumerate(self.fields):
                if self.filtered_fields is None or v in self.filtered_fields:
                    field_names.append(v)
        return field_names

    @staticmethod
    def bulk_to_elasticsearch(es, bulk_queue):
        try:
            helpers.bulk(es, bulk_queue)
            return True
        except:
            print(print_exc())
            return False

    @staticmethod
    def batch_to_elk(filepath=None, batch_size=500, fields=None, elk_ip="127.0.0.1", index="zeeklogs", meta={},
                     ignore_keys=[]):
        # Create handle to ELK
        es = Elasticsearch([elk_ip])

        # Create a handle to the log data
        dataHandle = ParseZeekLogs(filepath, fields=fields, output_format="json", meta=meta)

        # Begin to process and output data
        dataBatch = []
        for record in dataHandle:
            try:
                record = loads(record)

                if isinstance(record, dict):
                    record["_index"] = index
                    record["_type"] = index
                    try:
                        record['timestamp'] = datetime.utcfromtimestamp(float(record['ts'])).isoformat()
                    except:
                        pass

                    dataBatch.append(record)

                    if len(dataBatch) >= batch_size:
                        # Batch the queue to ELK
                        # print("Batching to elk: " + str(len(dataBatch)))
                        dataHandle.bulk_to_elasticsearch(es, dataBatch)
                        # Clear the data queue
                        dataBatch = []
            except:
                pass

        # Batch the final data to ELK
        # print("Batching final data to elk: " + str(len(dataBatch)))
        dataHandle.bulk_to_elasticsearch(es, dataBatch)
        # Clear the data queue
        dataBatch = []

    def __str__(self):
        return dumps(self.data)
