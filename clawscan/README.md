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
- **Exit codes:** 0 when a scan completed, whatever it found. 1 when there is no
  result (no key, out of credits, rate limited, unreachable, errored), with the
  reason in the JSON and `not_an_all_clear: true`. A failed scan never reads as
  a clean one.

Sample profile: [profile.example.yaml](profile.example.yaml).

## Tested

Against the live API on 2026-09-23, and again on 2026-10-20, with the fixtures in this directory:

| fixture | verdict | rule |
|---|---|---|
| `fixtures/exfil-skill` (markdown image that templates the conversation into an outside URL) | flagged, high | `pi.markdown_exfil` |
| `fixtures/benign-skill` (plain SKILL.md plus a helper script) | clear, `complete: false` | none; `helper.js` listed as not scanned |

Not yet tested: running it under ClawScan itself. The contract it follows (one
JSON object on stdout, explicit failure) is taken from ClawScan's docs.

What this is: signals, not a warranty. A clean verdict means these rules found
nothing, not that a skill is harmless.
