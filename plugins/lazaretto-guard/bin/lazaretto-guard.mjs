#!/usr/bin/env node
/**
 * The hand-run half of the plugin. Not a hook: exit codes here are ordinary.
 *
 *   lazaretto-guard hash   <path>
 *       Print the canonical hash of what is on disk. No network.
 *
 *   lazaretto-guard verify <path> <expected-hash>
 *       Compare what is on disk to a hash you already have. No network.
 *       The expected hash comes from you: nothing here hashes a package
 *       before it is installed, so there is no hash of ours to compare to.
 *       Exit 1 on a mismatch.
 *
 *   lazaretto-guard lookup <path>
 *       Hash-only network mode. Sends a sha256 of the content and nothing
 *       else: no name, no version, no path. Refused when the mode is offline.
 *
 *   lazaretto-guard check  <name@version> [...]
 *       The same call the hook makes, run by hand.
 */
import { hashPath, verifyInstalled } from '../lib/hash.mjs';
import { parseSpec } from '../lib/parse.mjs';
import { checkSpecs } from '../lib/api.mjs';
import { settingsFromEnv } from '../lib/decide.mjs';
import { CLIENT_TAG, VERSION } from '../lib/version.mjs';

const USAGE = `lazaretto-guard ${VERSION}

  hash   <path>                    canonical hash of what is on disk (no network)
  verify <path> <expected-hash>    compare on-disk bytes to a hash you have (no network)
  lookup <path>                    send only a sha256 of the content, nothing else
  check  <name@version> [...]      the call the hook makes, run by hand

Environment:
  LAZARETTO_GUARD_MODE=full|hash|offline|off
  LAZARETTO_GUARD_DISABLE=1
  LAZARETTO_GUARD_API=<origin>
`;

function out(text) {
  process.stdout.write(`${text}\n`);
}

async function main(argv) {
  const [cmd, ...args] = argv.slice(2);
  const settings = settingsFromEnv(process.env);

  if (cmd === 'hash') {
    if (args.length < 1) {
      out(USAGE);
      return 64;
    }
    out(hashPath(args[0]));
    return 0;
  }

  if (cmd === 'verify') {
    if (args.length < 2) {
      out(USAGE);
      return 64;
    }
    const result = verifyInstalled(args[0], args[1]);
    out(`${result.message}\n  on disk:  ${result.actual}\n  expected: ${result.expected}`);
    return result.match ? 0 : 1;
  }

  if (cmd === 'lookup') {
    if (args.length < 1) {
      out(USAGE);
      return 64;
    }
    if (settings.disabled) {
      out('lazaretto-guard is switched off (LAZARETTO_GUARD_DISABLE=1).');
      return 0;
    }
    const digest = hashPath(args[0]).replace(/^sha256:/, '');
    if (settings.mode === 'offline') {
      out(`Offline mode: nothing was sent. The hash is ${digest}`);
      return 0;
    }
    const res = await fetch(`${settings.origin}/v1/known-bad/${encodeURIComponent(digest)}`, {
      headers: { accept: 'application/json', 'user-agent': CLIENT_TAG },
      signal: AbortSignal.timeout(settings.timeoutMs * 4),
    }).catch(() => null);
    if (res === null || res.status !== 200) {
      out('No answer. That is not an all-clear.');
      return 0;
    }
    out(await res.text());
    return 0;
  }

  if (cmd === 'check') {
    const specs = args.map(parseSpec).filter((s) => s !== null);
    if (specs.length === 0) {
      out('Nothing to check. Only exactly pinned versions can be checked, for example chalk@5.6.1.');
      return 0;
    }
    if (settings.disabled || settings.offline) {
      out('This mode sends nothing. Switch LAZARETTO_GUARD_MODE to full to use it.');
      return 0;
    }
    const answer = await checkSpecs(specs, {
      origin: settings.origin,
      path: settings.path,
      timeoutMs: settings.timeoutMs * 4,
      clientTag: CLIENT_TAG,
    });
    if (answer === null) {
      out('No answer. That is not an all-clear.');
      return 0;
    }
    if (answer.hits.length === 0) {
      out(`Nothing among the ${specs.length} checked matched a published advisory. A package can be hostile before anyone has reported it.`);
      return 0;
    }
    for (const hit of answer.hits) {
      out(`${hit.name}@${hit.version}  ${hit.ids.join(', ')}`);
    }
    return 0;
  }

  out(USAGE);
  return cmd === undefined || cmd === '--help' || cmd === '-h' ? 0 : 64;
}

main(process.argv)
  .then((code) => {
    process.exitCode = code;
  })
  .catch((e) => {
    process.stderr.write(`lazaretto-guard: ${e.message}\n`);
    process.exitCode = 1;
  });
