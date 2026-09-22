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

/** Longest hook input we will read. Bigger than any real Bash command. */
const MAX_STDIN_BYTES = 1_000_000;

const VERSION = '0.1.0';
const CLIENT_TAG = `lazaretto-guard/${VERSION}`;

/** Read stdin to the end, capped. Resolves to '' on any trouble. */
function readStdin() {
  return new Promise((resolve) => {
    let size = 0;
    const chunks = [];
    process.stdin.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_STDIN_BYTES) {
        resolve('');
        return;
      }
      chunks.push(chunk);
    });
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', () => resolve(''));
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
