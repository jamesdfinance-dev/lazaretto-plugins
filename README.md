**What leaves your machine. On a package install: the names and exact versions of the packages, sent over HTTPS to `https://lazaretto.dev/check`. When a command or a config file connects a remote MCP server: that server's URL, so our scanner can ask the server for its tool list itself, plus a free API key the plugin requests once and keeps in `~/.config/lazaretto/key`, readable only by you. A server URL that carries a secret (a query string, a user:password, or an auth header on the command) is never sent. Every request carries a fixed client string `lazaretto-guard/<version>`. Nothing else: not the command, not file paths, not the working directory, not the project name. `LAZARETTO_GUARD_MODE=advisories` keeps only the package check, and `offline` sends nothing at all.**

# lazaretto-guard

A Claude Code plugin with two checks, both before anything is installed or connected:

1. **Remote MCP servers.** When the agent runs `claude mcp add <name> <url>`, or writes a remote server into `.mcp.json`, the hook has Lazaretto's scanner connect to that server, list its tools, and read the text it hands an agent: tool names, descriptions, parameter schemas and server instructions. It looks for tool poisoning (hidden orders pointing the agent at private keys or config files), parameters built to carry secrets or your conversation out, standing orders about another server's tools, and invisible characters. If something is there, you are asked first, with the rule and where it was found. This is the part nobody else does at install time.
2. **Packages.** For an install with exactly pinned versions, it asks whether any of them match a published malicious-package advisory. On a match, you are asked, with the advisory ids.

On anything else it says nothing.

## What it does not do

It never blocks. The hook only ever returns `ask`, never `deny`, and it never exits non-zero. One wrong block inside an agent run is a permanent uninstall, and the decision belongs to you, not to a hook.

It never mentions paying. There is no upsell on this path, in the prompt or anywhere else. Blocking and then selling would read as pay to unblock. The server read uses a free key (a few reads a day, refilled daily); when it runs out, the read is skipped silently and the package check carries on.

It never puts the flagged text in front of you. When a server's tool text is flagged, the prompt names our rule, its description and where it was found, but never quotes the server's own words: those words are the injection attempt.

It never stalls an install. A package install gets a 1.6 second window and a remote server add gets 7 seconds, because reading a server's tools means connecting to it and people add a server rarely and on purpose; `hooks.json` declares 8 seconds above both. For a package install, the hook runs its own 1.6 second watchdog counted from the moment the process started, so node's own startup comes out of our budget rather than out of the window Claude Code is holding, and the network call gets whatever is left of that budget after startup and stdin, less 120 milliseconds to write the answer out, capped at 1.45 seconds. The tests hold a socket open forever, and separately push more than the input cap through a pipe that never closes, and assert the process still gets out on its own, with margin.

The cost of that window is real and worth stating: an answer slower than about 1.45 seconds is dropped, silently, because the alternative is a stalled install. The sample behind that is small, so here it is in full. Five consecutive calls to the live API from one machine on 2026-09-22, one package each, took 1047, 2617, 2580, 988 and 981 milliseconds. Two of those five were over the budget and would have been dropped. A dropped answer is a missed warning rather than a broken install, and it looks exactly like a clean one, which is the honest reason not to read silence as an all clear.

Those numbers are dated 2026-09-22 and were measured before the latency work now under way on the API side. If that work has landed by the time you read this, re-measure rather than trusting the figures above.

It says nothing about packages that did not match. An empty answer is an empty answer, not a clean bill of health. A package can be hostile before anyone has reported it.

## Where it fires, and the honest part

**On npm, this is not a differentiated check.** The malicious-package answer is a live query against public advisory data. The other install guards in the Claude Code catalog query the same public data, free, and so can you. There is no freshness claim to make here and none is made.

**The part that is not covered elsewhere** is the surface this audience actually installs on, where nobody runs an advisory lookup at all:

- `claude mcp add weather -- npx -y weather-mcp@1.4.0` has a package identity in it. The hook reads it.
- An MCP server written into `.mcp.json` or `.cursor/mcp.json` has one too. The hook reads the `command` and `args` of each server entry.
- `npx`, `pnpm dlx`, `bunx` fetch and run a package without installing it, which is how a lot of agent tooling arrives.

**The second part** is `/lazaretto-verify`, which re-hashes what actually landed on disk and compares it to a hash you already hold. Be clear about where that hash comes from, because it is not one the guard produced: the guard never hashes anything before an install, so there is nothing of its own to compare against. The expected hash is one you recorded yourself with `lazaretto-guard hash <path>` at a point you were willing to trust, or one the publisher gave you. A pre-install check answers a question about an identity, this name at this version, and it cannot answer a question about bytes that are not on the machine yet. Comparing the bytes to a hash you hold catches drift between then and now. It works with the network switched off.

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

## Also in this repository

- [`clawscan/`](clawscan/): Lazaretto as a command scanner for [ClawScan](https://github.com/openclaw/clawscan) custom profiles, for agent skills.
