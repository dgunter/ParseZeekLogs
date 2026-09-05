import os
import pathlib

import pytest

DATA = pathlib.Path(__file__).parent / "data"
ROOT = pathlib.Path(__file__).resolve().parents[1]

ES_URL = os.environ.get("PARSEZEEKLOGS_ES_URL", "http://localhost:9200")
REQUIRE_ES = os.environ.get("PARSEZEEKLOGS_REQUIRE_ES", "").lower() in {"1", "true", "yes"}


@pytest.fixture(scope="session")
def data_dir() -> pathlib.Path:
    return DATA


@pytest.fixture(scope="session")
def es_url() -> str:
    """URL of a live Elasticsearch, or skip (fail when PARSEZEEKLOGS_REQUIRE_ES is set)."""
    from elasticsearch import Elasticsearch

    client = Elasticsearch(ES_URL, request_timeout=5)
    try:
        if client.ping():
            return ES_URL
        reason = f"Elasticsearch at {ES_URL} did not answer ping"
    except Exception as exc:  # noqa: BLE001 - any transport problem means "not reachable"
        reason = f"Elasticsearch at {ES_URL} not reachable: {exc}"
    finally:
        client.close()
    if REQUIRE_ES:
        pytest.fail(reason)
    pytest.skip(reason)
