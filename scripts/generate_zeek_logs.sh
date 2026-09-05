#!/usr/bin/env sh
# Run Zeek (Docker) over every capture in a directory tree and write the logs it
# produces, in both TSV and JSON form, under an output directory:
#
#   scripts/generate_zeek_logs.sh .cache/PCAP-ATTACK .cache/zeek-logs
#
# Output layout: <out>/<capture path without extension>/{tsv,json}/*.log
# Used to build the test corpus for `pytest -m samples`.
set -eu
PCAP_DIR=$(cd "${1:?pcap dir}" && pwd)
OUT_DIR=$(mkdir -p "${2:?output dir}" && cd "$2" && pwd)
IMAGE="${ZEEK_IMAGE:-zeek/zeek:8.2.2}"

find "$PCAP_DIR" -type f \( -iname '*.pcap' -o -iname '*.pcapng' \) | sort | while IFS= read -r pcap; do
  rel=${pcap#"$PCAP_DIR"/}
  base=${rel%.*}
  for fmt in tsv json; do
    dest="$OUT_DIR/$base/$fmt"
    mkdir -p "$dest"
    extra=""
    [ "$fmt" = json ] && extra="LogAscii::use_json=T"
    # -D makes the run deterministic (fixed random seeds, so uids match between
    # the TSV and JSON passes); -C ignores bad checksums (common in lab
    # captures); `local` loads the default site policy so protocol analyzers
    # and their logs are enabled.
    docker run --rm \
      -v "$PCAP_DIR:/pcaps:ro" -v "$dest:/out" -w /out \
      "$IMAGE" zeek -D -C -r "/pcaps/$rel" local $extra \
      > "$dest/zeek.stdout" 2> "$dest/zeek.stderr" || echo "FAILED: $rel ($fmt)" >&2
  done
  printf '%s\t%s\n' "$(ls "$OUT_DIR/$base/tsv"/*.log 2>/dev/null | wc -l | tr -d ' ')" "$base"
done
