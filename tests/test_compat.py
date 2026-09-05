import json
from unittest import mock

import pytest

from parsezeeklogs import ParseZeekLogs, compat


def test_json_output_matches_2x_contract(data_dir):
    it = ParseZeekLogs(str(data_dir / "conn_2018.log"), output_format="json", meta={"src": "x"})
    first = json.loads(next(it))
    assert first["src"] == "x"
    assert first["id.orig_p"] == 137
    assert "local_orig" not in first  # unset values are omitted
    assert isinstance(first["ts"], float)
    assert it.get_fields()[:2] == ["ts", "uid"]
    assert it.data_types["ts"] == "time"
    assert it.options["path"] == "conn"
    assert 1 + sum(1 for _ in it) == 2164


def test_csv_output_quotes_strings_only(data_dir):
    it = ParseZeekLogs(
        str(data_dir / "conn_2018.log"),
        output_format="csv",
        safe_headers=True,
        fields=["ts", "id_orig_h", "id_resp_p", "local_orig"],
    )
    assert it.get_fields() == "ts,id_orig_h,id_resp_p,local_orig"
    assert next(it) == '1258790493.773208,"192.168.1.104",137,""'


def test_csv_lists_and_bools():
    import io

    from parsezeeklogs.reader import ZeekLog

    text = "#separator \\x09\n#fields\ta\tb\tc\n#types\tbool\tset[string]\tcount\nT\tx,y\t3\n"
    it = ParseZeekLogs.__new__(ParseZeekLogs)
    it.output_format = "csv"
    it.ignore_keys = set()
    it.meta = {}
    it.safe_headers = False
    it._log = ZeekLog(io.StringIO(text))
    it._records = it._log.records()
    it.fields = it._log.fields
    assert next(it) == '"T","x,y",3'


def test_dict_output_and_ignore_keys(data_dir):
    it = ParseZeekLogs(str(data_dir / "conn_2018.log"), ignore_keys=["uid", "history"])
    rec = next(it)
    assert isinstance(rec, dict)
    assert "uid" not in rec
    assert "history" not in rec
    assert "uid" not in it.fields
    assert "uid" not in it.data_types


def test_context_manager_and_stop_iteration(data_dir):
    with ParseZeekLogs(str(data_dir / "rdp_sharprdp" / "tsv" / "rdp.log")) as it:
        rows = list(it)
    assert rows
    with pytest.raises(StopIteration):
        next(it)


def test_bulk_to_elasticsearch_reports_failure_as_false():
    es = mock.Mock()
    with mock.patch("elasticsearch.helpers.bulk", side_effect=RuntimeError("down")):
        assert ParseZeekLogs.bulk_to_elasticsearch(es, [{"x": 1}]) is False
    with mock.patch("elasticsearch.helpers.bulk", return_value=(1, [])):
        assert ParseZeekLogs.bulk_to_elasticsearch(es, [{"x": 1}]) is True


def test_batch_to_elk_uses_new_loader(data_dir):
    with (
        mock.patch("parsezeeklogs.elastic.make_client") as make_client,
        mock.patch("parsezeeklogs.elastic.ZeekToElk") as loader_cls,
    ):
        loader_cls.return_value.load.return_value = "result"
        out = ParseZeekLogs.batch_to_elk(
            str(data_dir / "conn_2018.log"),
            batch_size=10,
            elk_ip="10.0.0.5:9200",
            index="idx",
            meta={"a": 1},
            fields=["ts"],
            ignore_keys=["x"],
        )
    assert out == "result"
    make_client.assert_called_once_with("10.0.0.5:9200")
    loader_cls.assert_called_once_with(
        make_client.return_value, index="idx", bulk_size=10, metadata={"a": 1}, fields=["ts"]
    )
    assert compat.ParseZeekLogs is ParseZeekLogs
