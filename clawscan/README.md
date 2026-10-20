# Lazaretto for ClawScan

A command scanner for ClawScan's custom profiles, the route its
[scanner docs](https://github.com/openclaw/clawscan/blob/main/docs/scanners.md)
give for evaluating an outside scanner before any built-in adapter.

```
LAZARETTO_API_KEY=... node lazaretto-scanner.mjs <skill-dir | owner/name[@version]>
```

- **Local skill directory:** sends `SKILL.md` and lists every other file under
  `not_scanned`, with `complete: false`, so a gate can tell a SKILL.md-only scan
  from a whole-skill one.
- **Published ClawHub skill** (`owner/name`): the whole package is fetched and
  scanned server side.
- **No result is never a pass.** When there is no scan result, the JSON has
  `status: "error"`, an `error_kind` (`unavailable`, `rate_limited`,
  `no_credits` or `config`), a reason and `not_an_all_clear: true`, and the
  process exits 1. ClawScan records exit codes 0 to 124 with valid JSON as a
  completed scanner, so the profile's `lazaretto-unavailable` rule fires on
  `status: error` and the gate is never `pass` for a scan that did not happen.
  (A reserved exit of 125 or more would mark the scanner failed, and failed
  scanners fire no gate rules, which would leave the gate at `pass`.)

## Running it under ClawScan

Host sandbox:

```
LAZARETTO_API_KEY=... clawscan ./my-skill --config clawscan.yml --profile review --sandbox off
```

Docker sandbox (ClawScan's default; the runtime image already has Node). Mount
this directory read-only and let the key through:

```
LAZARETTO_API_KEY=... clawscan ./my-skill --config clawscan.yml --profile review \
  --sandbox-mount /abs/path/to/clawscan --sandbox-env LAZARETTO_API_KEY
```

The command in the profile must use the same absolute path.

Sample profile: [profile.example.yaml](profile.example.yaml).

## Evaluated under ClawScan

`eval/run-eval.sh` runs this scanner through ClawScan for five cases and checks
each artifact: a flagged skill, a clean skill with a file left unscanned, and an
unreachable, rate-limited and out-of-credits service. The
[ClawScan evaluation workflow](../.github/workflows/clawscan-eval.yml) runs it
in the Docker sandbox on every change and weekly against the live API, and
keeps the artifacts. It fails if any case passes the gate, or if the key
appears anywhere in an artifact.

## Tested by hand

Against the live API on 2026-09-23, and again on 2026-10-20, with the fixtures in this directory:

| fixture | verdict | rule |
|---|---|---|
| `fixtures/exfil-skill` (markdown image that templates the conversation into an outside URL) | flagged, high | `pi.markdown_exfil` |
| `fixtures/benign-skill` (plain SKILL.md plus a helper script) | clear, `complete: false` | none; `helper.js` listed as not scanned |

What this is: signals, not a warranty. A clean verdict means these rules found
nothing, not that a skill is harmless.
