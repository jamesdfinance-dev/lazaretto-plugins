# Install

What leaves your machine: package names and exact versions, and nothing else. Read the [README](README.md) before you install a hook that runs on every Bash call.

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

Ask the agent to run an install of a version that is in the advisory feed, for example a version the Lazaretto incident pages name at https://lazaretto.dev/caught. You should get a permission prompt carrying the advisory ids rather than a silent install. A clean install should produce no prompt at all and no visible delay.

You can also run the same check by hand, with no agent involved:

```
node plugins/lazaretto-guard/bin/lazaretto-guard.mjs check chalk@5.6.1
```

## Turn it off

Per session, or in your shell profile:

```
export LAZARETTO_GUARD_DISABLE=1
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

The hook reads both the terminal rendering that `/check` returns and the JSON that `/v1/lockfile` returns, so either path works.

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
