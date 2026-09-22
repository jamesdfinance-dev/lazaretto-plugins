**What leaves your machine: the names and exact versions of packages a command is about to install, sent over HTTPS to `https://lazaretto.dev/check`, plus a fixed client string `lazaretto-guard/<version>`. Nothing else. Not the command, not the file paths, not the working directory, not the project name, not an API key, because there is no key on this path. There is also a mode that sends nothing at all.**

# lazaretto-guard

A Claude Code plugin. When the agent is about to run an install, the hook reads the command, pulls out the exactly pinned package versions, and asks the Lazaretto API whether any of them match a published malicious-package advisory. On a match it returns `ask`, with the advisory ids, and you decide. On anything else it says nothing.

## What it does not do

It never blocks. The hook only ever returns `ask`, never `deny`, and it never exits non-zero. One wrong block inside an agent run is a permanent uninstall, and the decision belongs to you, not to a hook.

It never mentions paying. There is no upsell on this path, in the prompt or anywhere else. Blocking and then selling would read as pay to unblock.

It never stalls an install. `hooks.json` declares a 2 second timeout. Inside that the hook aborts the network call at 1.45 seconds and has its own 1.6 second watchdog, both counted from the moment the process started so node's own startup comes out of our budget rather than out of the window Claude Code is holding. The tests hold a socket open forever and assert the process still gets out on its own, with margin.

The cost of that window is real and worth stating: an answer slower than about 1.4 seconds is dropped, silently, because the alternative is a stalled install. Measured against the live API on 2026-09-22, a warm answer took about 1.0 second and a cold one about 2.6 seconds, so a cold answer is dropped today. A dropped answer is a missed warning, not a broken install, and it is indistinguishable from a clean one, which is the honest reason not to read silence as an all clear.

It says nothing about packages that did not match. An empty answer is an empty answer, not a clean bill of health. A package can be hostile before anyone has reported it.

## Where it fires, and the honest part

**On npm, this is not a differentiated check.** The malicious-package answer is a live query against public advisory data. The other install guards in the Claude Code catalog query the same public data, free, and so can you. There is no freshness claim to make here and none is made.

**The part that is not covered elsewhere** is the surface this audience actually installs on, where nobody runs an advisory lookup at all:

- `claude mcp add weather -- npx -y weather-mcp@1.4.0` has a package identity in it. The hook reads it.
- An MCP server written into `.mcp.json` or `.cursor/mcp.json` has one too. The hook reads the `command` and `args` of each server entry.
- `npx`, `pnpm dlx`, `bunx` fetch and run a package without installing it, which is how a lot of agent tooling arrives.

**The second part** is `/lazaretto-verify`, which re-hashes what actually landed on disk and compares it to the hash that was checked. A pre-install check answers a question about an identity. It cannot answer a question about bytes that are not on the machine yet. This closes that gap after the fact, and it works with the network switched off.

## What it can and cannot read

It only reports on **exactly pinned versions**, because that is the only thing an advisory feed can answer. `npm install chalk@5.6.1` is checked. `npm install chalk`, `npm install chalk@^5.0.0` and a bare `npm install` are not, and the hook stays silent on all three rather than guessing.

A command it cannot read confidently, for example one containing `$(...)`, an unterminated quote, or a backtick, produces nothing at all. Silence is the right answer far more often than a guess.

An agent skill or MCP server installed from a git URL has no registry identity, so there is no advisory to look up and the hook stays silent. `/lazaretto-verify` is what applies there.

## Modes

Set `LAZARETTO_GUARD_MODE`:

| Mode | What leaves the machine |
| --- | --- |
| `full` (default) | Package names and exact versions, on install commands only. |
| `hash` | Nothing from the hook. `lazaretto-guard lookup <path>` sends only a sha256 of content already on your disk: no name, no version, no path. |
| `offline` | Nothing, ever. `hash` and `verify` still work, entirely locally. |
| `off` | The hook does nothing. Same as `LAZARETTO_GUARD_DISABLE=1`. |

The request also reveals your IP address to the server, the same as any HTTPS request. If that matters for your work, use `offline`.

Other settings: `LAZARETTO_GUARD_API` (a different origin), `LAZARETTO_GUARD_API_PATH`, `LAZARETTO_GUARD_TIMEOUT_MS`, `LAZARETTO_GUARD_BUDGET_MS`.

## Install

See [INSTALL.md](INSTALL.md).

## Cost

The check is free, keyless and anonymous. The API rate limits it per IP, and a rate limit is answered with silence like any other non answer.

## Layout

```
.claude-plugin/marketplace.json   the marketplace manifest
plugins/lazaretto-guard/
  .claude-plugin/plugin.json      the plugin manifest, with an explicit version
  hooks/hooks.json                PreToolUse on Bash, and on Write/Edit for MCP config
  hooks/guard.mjs                 the hook process
  lib/tokenize.mjs                a small shell tokenizer that refuses what it cannot read
  lib/parse.mjs                   install command to pinned package identities
  lib/api.mjs                     the one place that touches the network
  lib/decide.mjs                  ask, or nothing
  lib/hash.mjs                    the on-disk re-hash, network free
  bin/lazaretto-guard.mjs         hash, verify, lookup, check, by hand
  commands/lazaretto-verify.md    the slash command
  test/                           node --test, no dependencies
```

No runtime dependencies. Node built-ins only, so the whole thing is short enough to read before you trust it.

## Tests

```
cd plugins/lazaretto-guard && node --test test/*.test.mjs
```

## Licence

MIT. See [LICENSE](LICENSE).
