# Install

What leaves your machine: on an install command, package names and exact versions; when a remote MCP server is being connected, that server's URL and a free key the plugin requests once. A URL carrying a secret is never sent. Nothing else. Read the [README](README.md) before you install a hook that runs on every Bash call and every file write.

## Requirements

Claude Code, and Node 20 or newer on your `PATH`. The plugin has no other dependencies.

## From this marketplace

In a Claude Code session:

```
/plugin marketplace add jamesdfinance-dev/lazaretto-plugins
/plugin install lazaretto-guard@lazaretto-plugins
```

Restart the session so the hook loads. To check it is there:

```
/plugin list
```

## From a local checkout, to read it first

```
git clone https://github.com/jamesdfinance-dev/lazaretto-plugins.git
cd lazaretto-plugins
node --test plugins/lazaretto-guard/test/*.test.mjs
```

Then, in Claude Code, with the absolute path to the checkout:

```
/plugin marketplace add /absolute/path/to/lazaretto-plugins
/plugin install lazaretto-guard@lazaretto-plugins
```

## Check that it works, without installing anything malicious

For the server read, ask the agent to run this:

```
claude mcp add --transport http lazaretto-demo https://lazaretto.dev/demo/mcp
```

The demo server is harmless on purpose: its one tool carries an `<IMPORTANT>` block that only asks the agent to say it is a demo. You should get a permission prompt naming the rule and where it was found. Choose no. The hook watches the agent's tool calls, so typing the command in your own terminal does not trigger it. If no prompt appears, the read was skipped: the API issues one free key per IP address per day, so another machine on the same address may already have taken today's.

For the package check, ask the agent to run an install of a version that is in the advisory feed, for example a version the Lazaretto incident pages name at https://lazaretto.dev/caught. You should get a permission prompt carrying the advisory ids rather than a silent install.

A clean install produces no prompt. It is not free, though: the hook adds up to about 1.5 seconds before the command runs, which is the API call plus node's own startup, and on a slow answer it spends the whole window and then says nothing. A warm answer is nearer one second. Connecting a remote server can take up to 7 seconds, because the scanner has to connect to it and list its tools. If that cost is not worth it to you, `LAZARETTO_GUARD_MODE=offline` removes it.

You can also run the same check by hand, with no agent involved:

```
node plugins/lazaretto-guard/bin/lazaretto-guard.mjs check chalk@5.6.1
```

## Turn it off

Per session, or in your shell profile:

```
export LAZARETTO_GUARD_DISABLE=1
```

Keep the package check, but never send a server URL or request a key:

```
export LAZARETTO_GUARD_MODE=advisories
```

Send nothing at all, keeping the local hash tools:

```
export LAZARETTO_GUARD_MODE=offline
```

Remove it:

```
/plugin uninstall lazaretto-guard@lazaretto-plugins
```

## Point it somewhere else

```
export LAZARETTO_GUARD_API=https://your-own-host
export LAZARETTO_GUARD_API_PATH=/v1/lockfile
```

The hook reads both the terminal rendering that `/check` returns and the JSON that `/v1/lockfile` returns, so either path works. The server read uses the same origin, calling `/v1/trial` for the free key and `/v1/scan` for the read.

## Verify what landed on disk

```
/lazaretto-verify node_modules/some-package <hash you recorded earlier>
```

or directly:

```
node plugins/lazaretto-guard/bin/lazaretto-guard.mjs hash node_modules/some-package
node plugins/lazaretto-guard/bin/lazaretto-guard.mjs verify node_modules/some-package sha256:...
```

Both run entirely on this machine.
