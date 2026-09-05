"""Corpus test over every Zeek log generated from PCAP-ATTACK.

    scripts/generate_zeek_logs.sh .cache/PCAP-ATTACK .cache/zeek-logs
    uv run pytest -m samples

Skipped unless PARSEZEEKLOGS_SAMPLES_DIR (default .cache/zeek-logs) exists.
"""

import os
import pathlib

import pytest

from parsezeeklogs.reader import decode_escapes, read_zeek

ROOT = pathlib.Path(__file__).resolve().parents[1]
SAMPLES_DIR = pathlib.Path(os.environ.get("PARSEZEEKLOGS_SAMPLES_DIR", ROOT / ".cache/zeek-logs"))
TSV_LOGS = sorted(SAMPLES_DIR.glob("**/tsv/*.log")) if SAMPLES_DIR.is_dir() else []

pytestmark = [
    pytest.mark.samples,
    pytest.mark.skipif(not TSV_LOGS, reason=f"no generated Zeek logs under {SAMPLES_DIR}"),
]


def _id(path: pathlib.Path) -> str:
    return str(path.relative_to(SAMPLES_DIR))


#: Values in these logs describe the Zeek run (CPU, memory, start time), not the
#: traffic, so they legitimately differ between the TSV and JSON passes.
RUN_DEPENDENT_LOGS = frozenset({"telemetry.log", "stats.log", "packet_filter.log"})


def _decode(value):
    if isinstance(value, str):
        return decode_escapes(value)
    if isinstance(value, list):
        return [decode_escapes(v) if isinstance(v, str) else v for v in value]
    return value


def _equivalent(tsv_rec, json_rec):
    for key, value in tsv_rec.items():
        if value is None:
            assert key not in json_rec, key
            continue
        assert key in json_rec, key
        other = json_rec[key]
        if isinstance(value, float) or (
            isinstance(value, list) and value and isinstance(value[0], float)
        ):
            assert other == pytest.approx(value, abs=1e-6), key
        elif value == [] and other == [""]:
            continue  # TSV renders both an empty set and {""} as (empty)
        elif other != value:
            # Zeek's JSON writer leaves non-printable bytes as literal "\\xHH" text
            assert _decode(other) == value, key
    assert set(json_rec) <= set(tsv_rec)


@pytest.mark.parametrize("tsv_path", TSV_LOGS, ids=_id)
def test_tsv_parses_and_matches_json(tsv_path):
    json_path = tsv_path.parent.parent / "json" / tsv_path.name
    data_lines = sum(1 for line in tsv_path.open() if line[0] != "#" and line.strip())
    tsv_records = list(read_zeek(tsv_path))
    assert len(tsv_records) == data_lines
    if json_path.exists():
        json_records = list(read_zeek(json_path))
        assert len(json_records) == len(tsv_records)
        if tsv_path.name not in RUN_DEPENDENT_LOGS:
            for a, b in zip(tsv_records, json_records, strict=True):
                _equivalent(a, b)
