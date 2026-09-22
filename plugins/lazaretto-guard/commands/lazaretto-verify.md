---
description: Re-hash what an install put on disk and compare it to a hash the user already holds
allowed-tools: Bash(node:*)
disable-model-invocation: false
---

Re-hash an installed package or skill on disk and compare it to a hash the user already holds.

The expected hash comes from the user, not from this plugin. The guard never hashes anything before an install, so there is no hash of its own on either side of the comparison. The user's hash is one they recorded earlier with `lazaretto-guard hash` on a copy they were willing to trust, or one the publisher gave them.

The pre-install check answers a question about an identity: this name at this version. It cannot answer a question about the bytes, because the bytes are not on the machine yet. This compares the bytes that are there now to what the user expected.

Run, with `$ARGUMENTS` giving the path and, when the user has one, the expected hash:

- With a path and an expected hash:
  `node "${CLAUDE_PLUGIN_ROOT}/bin/lazaretto-guard.mjs" verify <path> <expected-hash>`
- With a path only, to produce the hash to record:
  `node "${CLAUDE_PLUGIN_ROOT}/bin/lazaretto-guard.mjs" hash <path>`

Both run entirely on this machine and send nothing.

Report the result plainly. A match means the bytes on disk are the bytes the user's hash names. It does not mean the package was reviewed, and it says nothing about whether those bytes carry risk. A mismatch means what is installed is not what the user expected, so treat it as unverified and say so.
