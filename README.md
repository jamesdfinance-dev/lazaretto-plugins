**What leaves your machine. On a package install: the names and exact versions of the packages, sent over HTTPS to `https://lazaretto.dev/check`. When a command or a config file connects a remote MCP server: that server's URL, so our scanner can ask the server for its tool list itself, plus a free API key the plugin requests once and keeps in `~/.config/lazaretto/key`, readable only by you. Once a day, when a Claude Code session starts, the URLs of the remote servers you added that way are sent again with the same key, so their tools can be read again and compared with what they advertised when you added them. A server URL that carries a secret (a query string, a user:password, or an auth header on the command) is never sent. Every request carries a fixed client string `lazaretto-guard/<version>`. Nothing else: not the command, not file paths, not the working directory, not the project name. `LAZARETTO_GUARD_MODE=advisories` keeps only the package check, and `offline` sends nothing at all.**

# lazaretto-guard

A Claude Code plugin with two checks, both before anything is installed or connected:

1. **Remote MCP servers.** When the agent runs `claude mcp add <name> <url>`, or writes a remote server into `.mcp.json`, the hook has Lazaretto's scanner connect to that server, list its tools, and read the text it hands an agent: tool names, descriptions, parameter schemas and server instructions. It looks for tool poisoning (hidden orders pointing the agent at private keys or config files), parameters built to carry secrets or your conversation out, standing orders about another server's tools, and invisible characters. If something is there, you are asked first, with the rule and where it was found. This is the part nobody else does at install time.
2. **Tool changes after you approved a server.** A server can pass that read and change its tool descriptions a week later. Claude Code approved it once and never looks again. So the add keeps a fingerprint of what the server advertised (one SHA-256 per tool and one over all of them plus the instructions) in `~/.config/lazaretto/pins.json`, readable only by you, keyed by the server URL. Once a day at session start the hook reads each pinned server again. If the fingerprint differs, the session start names which tools were added, removed or changed, and you are asked before the first call to one of that server's tools. Names only, never the new tool text. You are asked once per change: after that, the new tools are the pin.
3. **Packages.** For an install with exactly pinned versions, it asks whether any of them match a published malicious-package advisory. On a match, you are asked, with the advisory ids.

On anything else it says nothing.

Not using Claude Code, or want to look before you install? The same server check runs in a browser at
[lazaretto.dev/check/mcp](https://lazaretto.dev/check/mcp), and the
[MCP registry index](https://lazaretto.dev/mcp-registry) shows the latest weekly read of every remote server in the
official MCP registry. Server operators can take a README badge from their server's page there.

## What it does not do

It never blocks. The hook only ever returns `ask`, never `deny`, and it never exits non-zero. One wrong block inside an agent run is a permanent uninstall, and the decision belongs to you, not to a hook.

It never mentions paying. There is no upsell on this path, in the prompt or anywhere else. Blocking and then selling would read as pay to unblock. The server read uses a free key (a few reads a day, refilled daily); when it runs out, the read is skipped silently and the package check carries on.

It never puts the flagged text in front of you. When a server's tool text is flagged, the prompt names our rule, its description and where it was found, but never quotes the server's own words: those words are the injection attempt.

It never stalls an install. A package install gets a 1.6 second window and a remote server add gets 7 seconds, because reading a server's tools means connecting to it and people add a server rarely and on purpose; `hooks.json` declares 8 seconds above both. The daily re-read of pinned servers gets 5 seconds at session start, at most once a day, and only when something is pinned; a server that misses the window, or cannot be reached, keeps its pin and is read again the next day. A call to an MCP tool reads the local pin file and sends nothing. For a package install, the hook runs its own 1.6 second watchdog counted from the moment the process started, so node's own startup comes out of our budget rather than out of the window Claude Code is holding, and the network call gets whatever is left of that budget after startup and stdin, less 120 milliseconds to write the answer out, capped at 1.45 seconds. The tests hold a socket open forever, and separately push more than the input cap through a pipe that never closes, and assert the process still gets out on its own, with margin.

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
| `full` (default) | Package names and exact versions, on install commands. When a remote MCP server is being connected, that server's URL and the free key. Once a day at session start, the URLs of pinned servers and the same key. |
| `advisories` | Package names and exact versions, on install commands only. No server URL is sent, no key is requested, and pinned servers are not read again. |
| `hash` | Nothing from the hook. `lazaretto-guard lookup <path>` sends only a sha256 of content already on your disk: no name, no version, no path. |
| `offline` | Nothing, ever. `hash` and `verify` still work, entirely locally. |
| `off` | The hook does nothing. Same as `LAZARETTO_GUARD_DISABLE=1`. |

Each request also reveals your IP address to the server, the same as any HTTPS request. If that matters for your work, use `offline`.

Other settings: `LAZARETTO_GUARD_API` (a different origin, for both checks), `LAZARETTO_GUARD_API_PATH`, `LAZARETTO_GUARD_TIMEOUT_MS`, `LAZARETTO_GUARD_BUDGET_MS`, `LAZARETTO_GUARD_MCP_TIMEOUT_MS`, `LAZARETTO_GUARD_MCP_BUDGET_MS`, `LAZARETTO_GUARD_SESSION_TIMEOUT_MS`, `LAZARETTO_GUARD_SESSION_BUDGET_MS`, `LAZARETTO_API_KEY` (your own key for the server read, in place of the free one), `XDG_CONFIG_HOME` (moves the key and pin files to `$XDG_CONFIG_HOME/lazaretto/`).

`lazaretto-guard pins` lists the pinned servers, and `lazaretto-guard unpin <url>` forgets one, for example a server you have removed. Neither touches the network.

## Install

See [INSTALL.md](INSTALL.md).

## Cost

The package check is free, keyless and anonymous. The API rate limits it per IP, and a rate limit is answered with silence like any other non answer.

The server read is free too, but it needs a key. The first time a remote server is connected, the plugin asks the API for a free key and saves it to `~/.config/lazaretto/key`, readable only by you. The API issues one free key per IP address per day. The key carries a few reads a day, refilled daily; when they run out, or when no key could be issued, the read is skipped silently and the package check carries on. If you set `LAZARETTO_API_KEY`, the read uses that key instead and spends its credits. The daily re-read of pinned servers spends reads from the same key; a session start never asks for a new key.

## Layout

```
.claude-plugin/marketplace.json   the marketplace manifest
plugins/lazaretto-guard/
  .claude-plugin/plugin.json      the plugin manifest, with an explicit version
  hooks/hooks.json                PreToolUse on Bash, on Write/Edit for MCP config, and on MCP tool calls; SessionStart
  hooks/guard.mjs                 the hook process
  lib/tokenize.mjs                a small shell tokenizer that refuses what it cannot read
  lib/parse.mjs                   install command to pinned package identities
  lib/api.mjs                     the package advisory call
  lib/mcp-scan.mjs                the remote server read, and the free key
  lib/pins.mjs                    tool pins: save, compare, name what changed
  lib/paths.mjs                   where the key and pins are kept
  lib/version.mjs                 the client string sent with every request
  lib/decide.mjs                  ask, or nothing
  lib/hash.mjs                    the on-disk re-hash, network free
  bin/lazaretto-guard.mjs         hash, verify, lookup, check, pins, unpin, by hand
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
