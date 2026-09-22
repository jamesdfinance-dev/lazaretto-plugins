#!/usr/bin/env node
/**
 * The PreToolUse hook process.
 *
 * Contract with Claude Code:
 *   - reads the hook input JSON on stdin
 *   - prints either nothing, or one PreToolUse payload with
 *     permissionDecision "ask"
 *   - always exits 0
 *
 * It never exits 2. Exit 2 is a blocking error in Claude Code, and this hook is
 * not allowed to block anything, ever. Every failure path here is an ordinary
 * exit 0 with no output.
 *
 * It also cannot hang the install it is sitting in front of. Three separate
 * limits enforce that: the fetch has its own abort timeout, this process has a
 * hard watchdog that exits 0 on its own, and hooks.json declares a 2 second
 * timeout so Claude Code kills it even if both of those are wrong.
 */
import { decide, settingsFromEnv } from '../lib/decide.mjs';
import { CLIENT_TAG } from '../lib/version.mjs';

/** Longest hook input we will read. Bigger than any real Bash command. */
const MAX_STDIN_BYTES = 1_000_000;

/**
 * Read stdin to the end, capped. Resolves to '' on any trouble.
 *
 * Whichever way it ends, it lets go of stdin first. Resolving while the stream
 * is still flowing leaves an open handle that holds the process up long after
 * it has decided to say nothing: on an over-cap read, with the writer still
 * holding the pipe open, that is the whole hook timeout spent doing nothing.
 */
function readStdin() {
  return new Promise((resolve) => {
    let size = 0;
    let settled = false;
    const chunks = [];

    const onData = (chunk) => {
      size += chunk.length;
      if (size > MAX_STDIN_BYTES) {
        finish('');
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => finish(Buffer.concat(chunks).toString('utf8'));
    const onError = () => finish('');

    function finish(value) {
      if (settled) return;
      settled = true;
      process.stdin.off('data', onData);
      process.stdin.off('end', onEnd);
      process.stdin.off('error', onError);
      process.stdin.pause();
      process.stdin.destroy();
      resolve(value);
    }

    process.stdin.on('data', onData);
    process.stdin.on('end', onEnd);
    process.stdin.on('error', onError);
  });
}

/** Milliseconds since this process started, node's own startup included. */
function sinceStart() {
  return process.uptime() * 1000;
}

async function main() {
  const settings = settingsFromEnv(process.env);

  // The watchdog, counted from process start rather than from here, so node's
  // own startup comes out of our budget and not out of the timeout Claude Code
  // is holding. If anything takes too long, including stdin never closing,
  // leave quietly rather than making the person wait.
  const watchdog = setTimeout(
    () => {
      process.exit(0);
    },
    Math.max(100, settings.budgetMs - sinceStart()),
  );

  let payload = null;
  try {
    const raw = await readStdin();
    if (raw !== '') {
      let input = null;
      try {
        input = JSON.parse(raw);
      } catch {
        input = null;
      }
      if (input !== null) {
        // Whatever is left of the budget after startup and stdin, less a little
        // room to write the answer out.
        const left = settings.budgetMs - sinceStart() - 120;
        const timeoutMs = Math.max(100, Math.min(settings.timeoutMs, left));
        payload = await decide(input, { settings: { ...settings, timeoutMs }, clientTag: CLIENT_TAG });
      }
    }
  } catch {
    payload = null;
  }

  clearTimeout(watchdog);
  if (payload !== null) process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = 0;
}

main().catch(() => {
  process.exitCode = 0;
});
