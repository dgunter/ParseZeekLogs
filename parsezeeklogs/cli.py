"""Command line interface.

parsezeeklogs json  conn.log dns.log -o out.jsonl
parsezeeklogs csv   conn.log --fields ts,uid,id.orig_h -o conn.csv
parsezeeklogs fields conn.log
parsezeeklogs elk   conn.log http://localhost:9200 -i zeeklogs --create-index
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import IO, Any

from parsezeeklogs import __version__
from parsezeeklogs.reader import ZeekLog, write_csv, write_json_lines

log = logging.getLogger(__name__)


def _json_object(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise argparse.ArgumentTypeError("metadata must be a JSON object")
    return value


def _field_list(text: str) -> list[str]:
    fields = [f.strip() for f in text.split(",") if f.strip()]
    if not fields:
        raise argparse.ArgumentTypeError("expected a comma-separated list of field names")
    return fields


def _add_read_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("logfile", nargs="+", help="Zeek log files (TSV or JSON, .gz accepted)")
    parser.add_argument(
        "-f", "--fields", type=_field_list, metavar="A,B,...", help="only keep these fields"
    )
    parser.add_argument(
        "--safe-headers", action="store_true", help="rewrite dots in field names to underscores"
    )
    parser.add_argument(
        "-m",
        "--meta",
        type=_json_object,
        metavar="JSON",
        help='JSON object merged into every record, e.g. \'{"sensor": "dmz"}\'',
    )
    parser.add_argument(
        "--time-format",
        choices=["epoch", "iso"],
        default="epoch",
        help="how Zeek time values are emitted (default: epoch seconds)",
    )


def _add_ecs_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ecs",
        action="store_true",
        help="emit Elastic Common Schema documents laid out like the Filebeat Zeek module",
    )


def _add_output_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-o", "--output", metavar="FILE", default="-", help="output file (default: stdout)"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="parsezeeklogs",
        description="Read Zeek logs; convert to JSON or CSV; load into Elasticsearch.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_json = sub.add_parser("json", help="convert to JSON lines")
    _add_read_options(p_json)
    _add_output_option(p_json)
    _add_ecs_option(p_json)

    p_csv = sub.add_parser("csv", help="convert to CSV")
    _add_read_options(p_csv)
    _add_output_option(p_csv)
    p_csv.add_argument("--no-header", action="store_true", help="omit the header row")

    p_fields = sub.add_parser("fields", help="list the fields and Zeek types of a log")
    p_fields.add_argument("logfile", help="Zeek log file")

    p_elk = sub.add_parser(
        "elk", help="bulk-load into Elasticsearch (needs the elasticsearch extra)"
    )
    _add_read_options(p_elk)
    p_elk.add_argument("url", help="Elasticsearch URL, e.g. http://localhost:9200")
    p_elk.add_argument("-i", "--index", default="zeeklogs", help="target index (default: zeeklogs)")
    p_elk.add_argument(
        "-s", "--bulk-size", type=int, default=500, help="documents per bulk request (default: 500)"
    )
    p_elk.add_argument(
        "--create-index", action="store_true", help="create the index with a mapping"
    )
    _add_ecs_option(p_elk)
    auth = p_elk.add_argument_group("authentication and TLS")
    auth.add_argument("-u", "--user", help="basic-auth user name")
    auth.add_argument("-p", "--password", help="basic-auth password (prompted if omitted)")
    auth.add_argument("--api-key", help="Elasticsearch API key")
    auth.add_argument("--ca-certs", metavar="PEM", help="CA bundle used to verify the server")
    auth.add_argument("-k", "--insecure", action="store_true", help="skip certificate verification")
    p_elk.add_argument("--timeout", type=float, default=60, help="request timeout in seconds")
    return parser


def _fail(message: str, exc: BaseException) -> int:
    log.error("%s: %s", message, exc)
    log.debug("traceback:", exc_info=exc)
    return 1


def resolve_output_path(output: str) -> Path:
    """Validate a user-supplied output path: parent must exist, target must not be a directory."""
    target = Path(output).expanduser().resolve()
    if not target.parent.is_dir():
        raise FileNotFoundError(f"output directory does not exist: {target.parent}")
    if target.is_dir():
        raise IsADirectoryError(f"output path is a directory: {target}")
    return target


class _Output:
    """Context manager yielding stdout for '-' or an opened file otherwise."""

    def __init__(self, output: str) -> None:
        self.output = output
        self._fh: IO[str] | None = None

    def __enter__(self) -> IO[str]:
        if self.output == "-":
            return sys.stdout
        self._fh = resolve_output_path(self.output).open("w", encoding="utf-8", newline="")
        return self._fh

    def __exit__(self, *exc: object) -> None:
        if self._fh is not None:
            self._fh.close()


def _records(args: argparse.Namespace) -> Iterator[dict[str, Any]]:
    ecs = getattr(args, "ecs", False)
    if ecs:
        from parsezeeklogs.ecs import to_ecs
    for path in args.logfile:
        with ZeekLog(
            path,
            fields=args.fields,
            safe_headers=args.safe_headers,
            meta=None if ecs else args.meta,
            time_format="epoch" if ecs else args.time_format,
        ) as zeek_log:
            if ecs:
                log_path = zeek_log.path
                for record in zeek_log:
                    yield to_ecs(record, log_path, args.meta)
            else:
                yield from zeek_log


def _run_json(args: argparse.Namespace) -> int:
    with _Output(args.output) as out:
        count = write_json_lines(_records(args), out)
    if args.output != "-":
        log.info("%d records written to %s", count, args.output)
    return 0


def _run_csv(args: argparse.Namespace) -> int:
    fields = args.fields
    if fields is None:
        with ZeekLog(args.logfile[0], safe_headers=args.safe_headers) as first:
            fields = first.fields or None
    if fields is not None and args.meta:
        fields = [*fields, *(k for k in args.meta if k not in fields)]
    with _Output(args.output) as out:
        count = write_csv(_records(args), out, fields, header=not args.no_header)
    if args.output != "-":
        log.info("%d records written to %s", count, args.output)
    return 0


def _run_fields(args: argparse.Namespace) -> int:
    with ZeekLog(args.logfile) as zeek_log:
        if zeek_log.is_json:
            first = next(iter(zeek_log), {})
            for name, value in first.items():
                sys.stdout.write(f"{name}\t{type(value).__name__}\n")
            return 0
        for name, ztype in zeek_log.types.items():
            sys.stdout.write(f"{name}\t{ztype}\n")
    return 0


def _run_elk(args: argparse.Namespace) -> int:
    try:
        from parsezeeklogs.elastic import ZeekToElk, ensure_index, make_client
        from parsezeeklogs.elastic import _require_elasticsearch as require

        es_module = require()
    except ImportError as exc:
        return _fail("cannot load Elasticsearch support", exc)

    password = args.password
    if args.user and password is None:
        import getpass

        password = getpass.getpass(f"Password for {args.user}: ")
    es = make_client(
        args.url,
        user=args.user,
        password=password,
        api_key=args.api_key,
        ca_certs=args.ca_certs,
        verify_certs=not args.insecure,
        timeout=args.timeout,
    )
    loader = ZeekToElk(
        es,
        index=args.index,
        bulk_size=args.bulk_size,
        metadata=args.meta,
        fields=args.fields,
        ecs=args.ecs,
    )
    try:
        if args.create_index and ensure_index(es, args.index, ecs=args.ecs):
            log.info("created index %s", args.index)
        result = loader.load_many(args.logfile)
    except (es_module.ApiError, es_module.TransportError) as exc:
        return _fail("Elasticsearch error", exc)
    except OSError as exc:
        return _fail("cannot read input", exc)
    log.info("done: indexed=%d failed=%d skipped=%d", result.indexed, result.failed, result.skipped)
    for err in result.errors:
        log.error("bulk failure: %s", err)
    return 0 if result.ok else 1


_COMMANDS = {"json": _run_json, "csv": _run_csv, "fields": _run_fields, "elk": _run_elk}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(message)s", stream=sys.stderr)
    logging.getLogger("parsezeeklogs").setLevel(level)
    logging.getLogger("elastic_transport").setLevel(logging.WARNING)
    try:
        return _COMMANDS[args.command](args)
    except BrokenPipeError:
        # Downstream (e.g. `head`) closed the pipe; that is not an error worth reporting.
        return 0
    except (OSError, ValueError) as exc:
        return _fail("error", exc)


if __name__ == "__main__":
    sys.exit(main())
