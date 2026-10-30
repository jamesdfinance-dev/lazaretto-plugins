**What leaves your machine: on a package install, the names and exact versions of the packages, sent over HTTPS to `https://lazaretto.dev/check`; when a remote MCP server is being connected, that server's URL and a free API key the plugin keeps in `~/.config/lazaretto/key`; once a day at session start, the URLs of servers added that way, to read their tools again. A URL carrying a secret is never sent. Every request carries `lazaretto-guard/<version>`. Nothing else, and `LAZARETTO_GUARD_MODE=offline` sends nothing at all.**

# lazaretto-guard

A PreToolUse hook. Before an agent connects a remote MCP server, it has Lazaretto read the tools that server advertises and asks first if the text carries poisoning or hidden orders. It keeps a fingerprint of those tools, reads the server again once a day at session start, and asks before the first call to its tools if they changed since you added it, naming which tools, never their text. Before an install, it checks the exactly pinned package versions against published malicious-package advisories and asks first on a match. On anything else, including a slow or unreachable API, it says nothing.

Install:

```
/plugin install lazaretto-guard --marketplace jamesdfinance-dev/lazaretto-plugins
```

It never returns `deny`, never exits non-zero, and never mentions paying.

The full README, including the honest account of what is and is not differentiated here, the modes, and what the hook cannot read, is at the root of this repository.

Run the tests with `node --test test/*.test.mjs`. No dependencies.
