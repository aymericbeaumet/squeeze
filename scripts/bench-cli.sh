#!/usr/bin/env bash
# Reproducible end-to-end benchmark of the squeeze CLI against other line
# matchers on the same extraction tasks.
#
#   scripts/bench-cli.sh [--scale N] [--runs N] [--out DIR] [--quick]
#
# Corpora are generated deterministically by the library's `scanner` bench
# (`--write-corpus`), each concatenated SCALE times (default 16, ~16 MiB per
# corpus), plus a `mixed` corpus that joins them all. Every tool reads the
# file directly (no pipes) with LC_ALL=C, output goes to /dev/null, and
# hyperfine reports wall-clock time after one warm-up run.
#
# Tasks map a squeeze finder to the closest POSIX ERE the other tools accept.
# The regexes are approximations of the finders' grammars: match counts are
# recorded next to the timings so differences in what each tool extracts stay
# visible. `all` runs squeeze with every finder (20 kinds); the regex tools
# run the union of the five task patterns.
#
# Requires: cargo, hyperfine, python3. Optional: rg, ugrep, GNU grep (ggrep),
# BSD grep (/usr/bin/grep). Missing tools are skipped.
set -euo pipefail

SCALE=16
RUNS=5
OUT=${BENCH_DIR:-/tmp/squeeze-bench}
QUICK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --scale) SCALE=$2; shift 2 ;;
    --runs) RUNS=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --quick) QUICK=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

ROOT=$(cd "$(dirname "$0")/.." && pwd)
for tool in cargo hyperfine python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done

mkdir -p "$OUT/corpus" "$OUT/results"
echo "== building release binary"
(cd "$ROOT" && cargo build --release --locked -p squeeze-cli >/dev/null 2>&1)
SQ="$ROOT/target/release/squeeze"

echo "== generating corpora (scale $SCALE)"
(cd "$ROOT" && cargo bench --locked -p squeeze --bench scanner -- \
  --write-corpus "$OUT/corpus" --only logs,prose,source,jsonl,markdown,hexdense,unicode >/dev/null 2>&1)
CORPORA=()
for f in "$OUT"/corpus/*.txt; do
  base=$(basename "$f" .txt)
  big="$OUT/$base.txt"
  : > "$big"
  for _ in $(seq 1 "$SCALE"); do cat "$f" >> "$big"; done
  CORPORA+=("$base")
done
cat "$OUT"/logs.txt "$OUT"/prose.txt "$OUT"/source.txt "$OUT"/jsonl.txt \
  "$OUT"/markdown.txt "$OUT"/hexdense.txt "$OUT"/unicode.txt > "$OUT/mixed.txt"
if [ "$QUICK" = 1 ]; then
  BENCH_CORPORA=(mixed)
else
  BENCH_CORPORA=(mixed logs prose)
fi

# --- competitor detection ------------------------------------------------
declare -a TOOLS=()   # name|command prefix (pattern and file appended)
if command -v rg >/dev/null 2>&1; then
  TOOLS+=("ripgrep|rg --no-config -oN --no-filename -e")
fi
if command -v ugrep >/dev/null 2>&1; then
  TOOLS+=("ugrep|ugrep -oE")
elif grep --version 2>/dev/null | head -1 | grep -q ugrep; then
  TOOLS+=("ugrep|grep -oE")
fi
if command -v ggrep >/dev/null 2>&1; then
  TOOLS+=("gnu grep|ggrep -oE")
elif grep --version 2>/dev/null | head -1 | grep -q GNU; then
  TOOLS+=("gnu grep|grep -oE")
fi
if [ -x /usr/bin/grep ] && ! /usr/bin/grep --version 2>/dev/null | head -1 | grep -qE 'GNU|ugrep'; then
  TOOLS+=("bsd grep|/usr/bin/grep -oE")
fi
JOBS=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

# --- tasks ---------------------------------------------------------------
# No quotes inside patterns: hyperfine -N splits commands without a shell.
URL='https?://[^[:space:]<>)]+'
EMAIL='[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:]][[:alpha:]]+'
IPV4='([0-9][0-9]?[0-9]?\.)[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?\.[0-9][0-9]?[0-9]?'
SHA256='[0-9a-f]{64}'
UUID='[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
declare -a TASKS=(
  "url|--url|$URL"
  "email|--email|$EMAIL"
  "ipv4|--ipv4|$IPV4"
  "sha256|--sha256|$SHA256"
  "uuid|--uuid|$UUID"
  "all|--all|$URL|$EMAIL|$IPV4|$SHA256|$UUID"
)

export LC_ALL=C
echo "== tools: squeeze, squeeze -j $JOBS, $(printf '%s\n' "${TOOLS[@]}" | cut -d'|' -f1 | paste -sd, -)"

for corpus in "${BENCH_CORPORA[@]}"; do
  file="$OUT/$corpus.txt"
  bytes=$(wc -c < "$file" | tr -d ' ')
  for task in "${TASKS[@]}"; do
    name=${task%%|*}
    rest=${task#*|}
    flags=${rest%%|*}
    pattern=${rest#*|}
    echo "== $corpus / $name ($bytes bytes)"
    args=(--warmup 1 --runs "$RUNS" -N --export-json "$OUT/results/$corpus-$name.json")
    counts="$OUT/results/$corpus-$name.counts"
    : > "$counts"
    args+=(-n "squeeze" "$SQ $flags $file")
    "$SQ" $flags "$file" | wc -l | tr -d ' ' | sed "s/^/squeeze /" >> "$counts"
    args+=(-n "squeeze -j $JOBS" "$SQ $flags -j $JOBS $file")
    "$SQ" $flags -j "$JOBS" "$file" | wc -l | tr -d ' ' | sed "s/^/squeeze -j $JOBS /" >> "$counts"
    for tool in "${TOOLS[@]}"; do
      tname=${tool%%|*}
      cmd=${tool#*|}
      args+=(-n "$tname" "$cmd '$pattern' $file")
      # shellcheck disable=SC2086
      $cmd "$pattern" "$file" 2>/dev/null | wc -l | tr -d ' ' | sed "s/^/$tname /" >> "$counts" || true
    done
    hyperfine "${args[@]}" >/dev/null 2>&1 || echo "   (hyperfine failed for $corpus/$name)"
  done
done

echo "== summary"
python3 - "$OUT" "${BENCH_CORPORA[@]}" <<'EOF'
import json, os, sys
out = sys.argv[1]
corpora = sys.argv[2:]
tasks = ["url", "email", "ipv4", "sha256", "uuid", "all"]
lines = []
for corpus in corpora:
    size = os.path.getsize(os.path.join(out, f"{corpus}.txt"))
    lines.append(f"\n### {corpus} ({size / 1048576:.0f} MiB)\n")
    header = None
    for task in tasks:
        path = os.path.join(out, "results", f"{corpus}-{task}.json")
        if not os.path.exists(path):
            continue
        data = json.load(open(path))
        counts = {}
        cpath = os.path.join(out, "results", f"{corpus}-{task}.counts")
        if os.path.exists(cpath):
            for line in open(cpath):
                parts = line.rsplit(" ", 1)
                if len(parts) == 2:
                    counts[parts[0]] = parts[1].strip()
        results = {r["command"]: r for r in data["results"]}
        if header is None:
            # Columns: every tool seen in any task of this corpus, in order.
            header = []
            for t in tasks:
                tp = os.path.join(out, "results", f"{corpus}-{t}.json")
                if os.path.exists(tp):
                    for r in json.load(open(tp))["results"]:
                        if r["command"] not in header:
                            header.append(r["command"])
            lines.append("| task | " + " | ".join(header) + " |")
            lines.append("|---|" + "---|" * len(header))
        cells = []
        for name in header:
            r = results.get(name)
            if r is None:
                cells.append("n/a")
                continue
            ms = r["mean"] * 1000
            mbs = size / r["mean"] / 1048576
            count = counts.get(name, "?")
            cells.append(f"{ms:.0f} ms ({mbs:.0f} MiB/s, {count} matches)")
        lines.append(f"| {task} | " + " | ".join(cells) + " |")
text = "\n".join(lines) + "\n"
open(os.path.join(out, "summary.md"), "w").write(text)
print(text)
EOF
echo "written to $OUT/summary.md (raw hyperfine JSON in $OUT/results)"
