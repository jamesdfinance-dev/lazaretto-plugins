**What leaves your machine: the names and exact versions of packages a command is about to install, sent over HTTPS to `https://lazaretto.dev/check`, plus a fixed client string `lazaretto-guard/<version>`. Nothing else, and there is a mode that sends nothing at all.**

# lazaretto-guard

A PreToolUse hook. Before an install runs, it reads the command, pulls out the exactly pinned package versions, and asks whether any of them match a published malicious-package advisory. On a match it returns `ask` with the advisory ids. On anything else, including a slow or unreachable API, it says nothing.

It never returns `deny`, never exits non-zero, and never mentions paying.

The full README, including the honest account of what is and is not differentiated here, the modes, and what the hook cannot read, is at the root of this repository.

Run the tests with `node --test test/*.test.mjs`. No dependencies.
