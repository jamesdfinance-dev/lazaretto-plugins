---
description: Re-hash what an install put on disk and compare it to the hash that was checked
allowed-tools: Bash(node:*)
disable-model-invocation: false
---

Re-hash an installed package or skill on disk and compare it to a hash the user already has.

The pre-install check answers a question about an identity: this name at this version. It cannot answer a question about the bytes, because the bytes are not on the machine yet. This closes that gap after the fact.

Run, with `$ARGUMENTS` giving the path and, when the user has one, the expected hash:

- With a path and an expected hash:
  `node "${CLAUDE_PLUGIN_ROOT}/bin/lazaretto-guard.mjs" verify <path> <expected-hash>`
- With a path only, to produce the hash to record:
  `node "${CLAUDE_PLUGIN_ROOT}/bin/lazaretto-guard.mjs" hash <path>`

Both run entirely on this machine and send nothing.

Report the result plainly. A match means the bytes on disk are the bytes that were checked. It does not mean the package is without risk. A mismatch means what is installed is not what was checked, so treat it as unchecked and say so.
