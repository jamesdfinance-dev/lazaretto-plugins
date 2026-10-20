#!/bin/sh
# Run the Lazaretto command scanner through real ClawScan, once per case, and
# check each artifact: scanner status, gate, which rule fired, and that the key
# never appears. Used by .github/workflows/clawscan-eval.yml; runs locally too.
#
#   sh clawscan/eval/run-eval.sh <docker|off> <out-dir>
#
# Needs: clawscan on PATH, node, python3, LAZARETTO_API_KEY (a free key works).
set -eu
MODE="$1"; OUT="$2"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$OUT"
: "${LAZARETTO_API_KEY:?set LAZARETTO_API_KEY (curl -s -X POST https://lazaretto.dev/v1/trial)}"
LIVE="${LAZARETTO_LIVE_API:-https://lazaretto.dev}"

cat > "$OUT/clawscan.yml" <<YAML
version: 1
profiles:
  review:
    scanners:
      - id: lazaretto
        command: node $HERE/lazaretto-scanner.mjs {{target}}
        env:
          - LAZARETTO_API
        secretEnv:
          - LAZARETTO_API_KEY
        targets:
          - skill
        gate:
          rules:
            - id: lazaretto-malicious
              path: verdict
              equals: malicious
              action: block
            - id: lazaretto-flagged
              path: verdict
              equals: flagged
              action: warn
            - id: lazaretto-partial
              path: not_scanned[]
              exists: true
              action: warn
            - id: lazaretto-unavailable
              path: status
              equals: error
              action: warn
YAML

# 429 and 402 come from a local stand-in, reachable from the host. Under Docker
# they are run with --sandbox off, since the container cannot see the host's
# loopback; every other case runs in the requested mode.
node "$HERE/eval/stub.mjs" "$OUT/stub.json" & STUB=$!
trap 'kill $STUB 2>/dev/null || true' EXIT
for i in $(seq 1 50); do [ -s "$OUT/stub.json" ] && break; sleep 0.2; done
LIM=$(python3 -c "import json;print(json.load(open('$OUT/stub.json'))['limit'])")
CRED=$(python3 -c "import json;print(json.load(open('$OUT/stub.json'))['credits'])")

run() { # name mode api target expect_rule expect_verdict expect_kind
  name="$1"; mode="$2"; api="$3"; target="$4"
  set -- --config "$OUT/clawscan.yml" --profile review --sandbox "$mode" --json
  if [ "$mode" = docker ]; then set -- "$@" --sandbox-mount "$HERE" --sandbox-env LAZARETTO_API --sandbox-env LAZARETTO_API_KEY; fi
  LAZARETTO_API="$api" clawscan "$target" "$@" > "$OUT/$name.json" 2> "$OUT/$name.stderr" || true
}

run flagged     "$MODE" "$LIVE"                    "$HERE/fixtures/exfil-skill"
run partial     "$MODE" "$LIVE"                    "$HERE/fixtures/benign-skill"
run unreachable "$MODE" "http://127.0.0.1:9"       "$HERE/fixtures/benign-skill"
run ratelimited off     "http://127.0.0.1:$LIM"    "$HERE/fixtures/benign-skill"
run nocredits   off     "http://127.0.0.1:$CRED"   "$HERE/fixtures/benign-skill"

python3 - "$OUT" "$MODE" <<'PY'
import json, os, sys
out, mode = sys.argv[1:]
key = os.environ["LAZARETTO_API_KEY"]
expect = {
    "flagged":     ("lazaretto-flagged",     "flagged", None),
    "partial":     ("lazaretto-partial",     "clear",   None),
    "unreachable": ("lazaretto-unavailable", None,      "unavailable"),
    "ratelimited": ("lazaretto-unavailable", None,      "rate_limited"),
    "nocredits":   ("lazaretto-unavailable", None,      "no_credits"),
}
failed = 0
lines = ["| case | sandbox | scanner | exit | gate | rule fired | verdict / error_kind | key in artifact |", "|---|---|---|---|---|---|---|---|"]
for name, (rule, verdict, kind) in expect.items():
    raw = open(f"{out}/{name}.json").read()
    try:
        a = json.loads(raw)
        s = a["scanners"]["lazaretto"]
    except Exception as e:
        print(f"{name}: no artifact ({e})"); print(open(f"{out}/{name}.stderr").read()[:2000]); failed += 1; continue
    r = s.get("raw") or {}
    fired = [g["rule"] for g in a.get("gateRules", [])]
    ok = (s.get("status") == "completed" and a.get("gate") != "pass" and rule in fired
          and (verdict is None or r.get("verdict") == verdict) and (kind is None or r.get("error_kind") == kind)
          and key not in raw)
    failed += 0 if ok else 1
    sandbox = a.get("sandbox", {}).get("mode")
    lines.append(f"| {name} | {sandbox} | {s.get('status')} | {s.get('exitCode')} | {a.get('gate')} | {', '.join(fired)} | {r.get('verdict') or r.get('error_kind')} | {key in raw} |" + ("" if ok else " FAIL"))
report = "\n".join(lines)
print(report)
open(f"{out}/summary.md", "w").write(report + "\n")
sys.exit(1 if failed else 0)
PY
