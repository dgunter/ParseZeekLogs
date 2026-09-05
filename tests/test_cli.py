import json
from unittest import mock

import pytest

from parsezeeklogs import cli

# Placeholder credential for argument-passing tests; nothing authenticates against it.
BASIC_AUTH_SECRET = "pw"

RDP = "rdp_sharprdp/tsv/rdp.log"


def _data_lines(path) -> int:
    with open(path, encoding="utf-8") as fh:
        return sum(1 for line in fh if not line.startswith("#"))


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "parsezeeklogs 3." in capsys.readouterr().out


def test_json_to_stdout(capsys, data_dir):
    assert cli.main(["json", str(data_dir / RDP), "-m", '{"s": 1}', "--time-format", "iso"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    first = json.loads(lines[0])
    assert first["s"] == 1
    assert first["ts"].endswith("+00:00")


def test_json_to_file_multiple_inputs(tmp_path, data_dir, caplog):
    out = tmp_path / "out.jsonl"
    rc = cli.main(
        ["json", str(data_dir / RDP), str(data_dir / RDP), "-o", str(out), "-f", "ts,uid"]
    )
    assert rc == 0
    lines = out.read_text().splitlines()
    assert len(lines) == 2 * _data_lines(data_dir / RDP)
    assert set(json.loads(lines[0])) == {"ts", "uid"}
    assert f"{len(lines)} records written" in caplog.text


def test_csv_default_fields_and_safe_headers(capsys, data_dir):
    assert cli.main(["csv", str(data_dir / RDP), "--safe-headers", "-m", '{"tag": "x"}']) == 0
    out = capsys.readouterr().out.splitlines()
    header = out[0].split(",")
    assert "id_orig_h" in header
    assert "tag" in header
    assert "." not in out[0]
    assert len(out) == 1 + _data_lines(data_dir / RDP)


def test_csv_no_header_and_fields(capsys, data_dir):
    assert cli.main(["csv", str(data_dir / RDP), "-f", "uid,cookie", "--no-header"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert not out[0].startswith("uid,")
    assert all(len(line.split(",")) >= 2 for line in out)


def test_csv_of_json_log_infers_fields(capsys, data_dir):
    assert cli.main(["csv", str(data_dir / "rdp_sharprdp/json/rdp.log")]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("ts,uid,")


def test_fields_command(capsys, data_dir):
    assert cli.main(["fields", str(data_dir / RDP)]) == 0
    out = capsys.readouterr().out
    assert "ts\ttime" in out
    assert "id.orig_h\taddr" in out
    assert cli.main(["fields", str(data_dir / "rdp_sharprdp/json/rdp.log")]) == 0
    out = capsys.readouterr().out
    assert "ts\tfloat" in out
    assert "uid\tstr" in out


@pytest.mark.parametrize("bad", ["not json", "[1]", '"s"'])
def test_meta_must_be_object(bad):
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["json", "x.log", "-m", bad])


def test_fields_option_rejects_empty():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["json", "x.log", "-f", " , "])


def test_missing_input_is_an_error(caplog):
    assert cli.main(["json", "/nonexistent.log"]) == 1
    assert "nonexistent" in caplog.text


def test_output_path_validation(tmp_path, data_dir, caplog):
    assert cli.main(["json", str(data_dir / RDP), "-o", str(tmp_path / "no" / "x.json")]) == 1
    assert "does not exist" in caplog.text
    assert cli.main(["json", str(data_dir / RDP), "-o", str(tmp_path)]) == 1
    with pytest.raises(FileNotFoundError):
        cli.resolve_output_path(str(tmp_path / "missing" / "f"))


def test_broken_pipe_is_quiet(data_dir):
    with mock.patch.object(cli, "write_json_lines", side_effect=BrokenPipeError):
        assert cli.main(["json", str(data_dir / RDP)]) == 0


def _run_elk(argv, result):
    es = mock.Mock()
    with (
        mock.patch("parsezeeklogs.elastic.make_client", return_value=es) as make_client,
        mock.patch("parsezeeklogs.elastic.ensure_index", return_value=True) as ensure,
        mock.patch("parsezeeklogs.elastic.ZeekToElk.load_many", return_value=result) as load_many,
    ):
        rc = cli.main(argv)
    return rc, make_client, ensure, load_many, es


def test_elk_passes_options(data_dir, caplog):
    from parsezeeklogs.elastic import LoadResult

    rc, make_client, ensure, load_many, es = _run_elk(
        [
            "elk",
            str(data_dir / RDP),
            "https://es:9200",
            "-i",
            "idx",
            "-s",
            "7",
            "-u",
            "elastic",
            "-p",
            BASIC_AUTH_SECRET,
            "--api-key",
            "k",
            "--ca-certs",
            "ca.pem",
            "-k",
            "--timeout",
            "3",
            "--create-index",
            "-m",
            '{"a": 1}',
        ],
        LoadResult(indexed=5),
    )
    assert rc == 0
    make_client.assert_called_once_with(
        "https://es:9200",
        user="elastic",
        password=BASIC_AUTH_SECRET,
        api_key="k",
        ca_certs="ca.pem",
        verify_certs=False,
        timeout=3.0,
    )
    ensure.assert_called_once_with(es, "idx", ecs=False)
    load_many.assert_called_once_with([str(data_dir / RDP)])
    assert "created index idx" in caplog.text


def test_elk_failures_return_1(data_dir, caplog):
    from parsezeeklogs.elastic import LoadResult

    rc, *_ = _run_elk(
        ["elk", str(data_dir / RDP), "localhost"], LoadResult(indexed=1, failed=1, errors=["boom"])
    )
    assert rc == 1
    assert "boom" in caplog.text


def test_elk_prompts_for_password(data_dir):
    from parsezeeklogs.elastic import LoadResult

    es = mock.Mock()
    with (
        mock.patch("parsezeeklogs.elastic.make_client", return_value=es) as make_client,
        mock.patch("parsezeeklogs.elastic.ZeekToElk.load_many", return_value=LoadResult()),
        mock.patch("getpass.getpass", return_value="typed"),
    ):
        assert cli.main(["elk", str(data_dir / RDP), "localhost", "-u", "elastic"]) == 0
    assert make_client.call_args.kwargs["password"] == "typed"


def test_elk_transport_error(data_dir, caplog):
    from elastic_transport import ConnectionError as ESConnectionError

    with (
        mock.patch("parsezeeklogs.elastic.make_client", return_value=mock.Mock()),
        mock.patch(
            "parsezeeklogs.elastic.ZeekToElk.load_many", side_effect=ESConnectionError("refused")
        ),
    ):
        assert cli.main(["elk", str(data_dir / RDP), "localhost"]) == 1
    assert "Elasticsearch error" in caplog.text


def test_elk_without_extra(data_dir, caplog):
    with mock.patch("parsezeeklogs.elastic._require_elasticsearch", side_effect=ImportError("x")):
        assert cli.main(["elk", str(data_dir / RDP), "localhost"]) == 1
    assert "Elasticsearch support" in caplog.text


def test_json_ecs_output(capsys, data_dir):
    assert (
        cli.main(
            [
                "json",
                str(data_dir / "rdp_sharprdp/tsv/conn.log"),
                "--ecs",
                "-m",
                '{"observer.name": "s1"}',
            ]
        )
        == 0
    )
    first = json.loads(capsys.readouterr().out.splitlines()[0])
    assert first["event"]["dataset"] == "zeek.connection"
    assert first["ecs"]["version"]
    assert first["source"]["ip"]
    assert first["observer"]["name"] == "s1"


def test_elk_ecs_flag_reaches_loader(data_dir):
    from parsezeeklogs.elastic import LoadResult

    es = mock.Mock()
    with (
        mock.patch("parsezeeklogs.elastic.make_client", return_value=es),
        mock.patch("parsezeeklogs.elastic.ensure_index", return_value=True) as ensure,
        mock.patch("parsezeeklogs.elastic.ZeekToElk.__init__", return_value=None) as init,
        mock.patch("parsezeeklogs.elastic.ZeekToElk.load_many", return_value=LoadResult()),
    ):
        assert cli.main(["elk", str(data_dir / RDP), "localhost", "--ecs", "--create-index"]) == 0
    assert init.call_args.kwargs["ecs"] is True
    ensure.assert_called_once_with(es, "zeeklogs", ecs=True)
