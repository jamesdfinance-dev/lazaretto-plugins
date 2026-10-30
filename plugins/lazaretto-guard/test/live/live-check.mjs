/**
 * The real hook against the live service, the way Claude Code calls it.
 *
 * Run daily by .github/workflows/guard-live-check.yml from a fresh machine:
 * it gets its own free key, then feeds the hook the exact PreToolUse input
 * Claude Code sends for four commands and checks what comes back. Then the
 * pinned demo: the add pins the demo server's tools, the pin is altered the
 * way a server changing its tools would look, and a session start and a call
 * to one of its tools must name the change. Labelled `+ci`, so the service
 * never counts this as someone using the plugin.
 *
 *   node plugins/lazaretto-guard/test/live/live-check.mjs
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, appendFileSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HOOK = fileURLToPath(new URL('../../hooks/guard.mjs', import.meta.url));
const ORIGIN = process.env.LAZARETTO_GUARD_API ?? 'https://lazaretto.dev';
const SUFFIX = 'ci';

const cases = [
  { name: 'MCP server with a poisoned tool (harmless demo)', command: 'claude mcp add --transport http lazaretto-demo https://lazaretto.dev/demo/mcp', expect: 'ask', mustInclude: 'mcp.directive_block' },
  { name: 'MCP server with clean tools', command: 'claude mcp add --transport http lazaretto https://lazaretto.dev/mcp', expect: 'silent' },
  { name: 'package listed as malware', command: 'npm install chalk@5.6.1', expect: 'ask', mustInclude: 'MAL-2025-46969' },
  { name: 'clean package', command: 'npm install left-pad@1.3.0', expect: 'silent' },
];

async function freeKey() {
  const res = await fetch(`${ORIGIN}/v1/trial`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-lazaretto-client': `lazaretto-guard/selftest+${SUFFIX}`, 'user-agent': `lazaretto-guard-selftest+${SUFFIX}` },
    body: '{}',
  });
  if (!res.ok) return null;
  const body = await res.json();
  return typeof body.api_key === 'string' ? body.api_key : null;
}

const key = process.env.LAZARETTO_API_KEY || (await freeKey());
if (!key) {
  console.log('::warning::Could not get a free key from this machine, so the MCP cases cannot run. Inconclusive, not a failure.');
  process.exit(0);
}
if (process.env.GITHUB_ACTIONS) console.log(`::add-mask::${key}`);

/** Run the hook once with one input. `got` is ask, message (a session start's systemMessage) or silent. */
function runHook(input, configHome) {
  const started = Date.now();
  const r = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify(input),
    encoding: 'utf8',
    timeout: 9000,
    env: { PATH: process.env.PATH, XDG_CONFIG_HOME: configHome, LAZARETTO_API_KEY: key, LAZARETTO_GUARD_API: ORIGIN, LAZARETTO_GUARD_CLIENT_SUFFIX: SUFFIX },
  });
  const ms = Date.now() - started;
  let got = 'silent';
  let text = '';
  if (r.stdout.trim() !== '') {
    try {
      const out = JSON.parse(r.stdout);
      if (out.hookSpecificOutput) {
        got = out.hookSpecificOutput.permissionDecision;
        text = out.hookSpecificOutput.permissionDecisionReason ?? '';
      } else if (typeof out.systemMessage === 'string') {
        got = 'message';
        text = out.systemMessage;
      } else {
        got = 'unreadable output';
      }
    } catch {
      got = 'unreadable output';
    }
  }
  return { status: r.status, got, text, ms };
}

const rows = ['| case | expected | got | time | result |', '|---|---|---|---|---|'];
let failed = 0;
function record(name, expect, mustInclude, r, extraOk = true) {
  const ok = r.status === 0 && r.got === expect && (!mustInclude || r.text.includes(mustInclude)) && extraOk;
  if (!ok) failed += 1;
  rows.push(`| ${name} | ${expect}${mustInclude ? ` (${mustInclude})` : ''} | ${r.got} | ${r.ms} ms | ${ok ? 'pass' : 'FAIL'} |`);
}

const bash = (command) => ({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });

for (const c of cases) {
  record(c.name, c.expect, c.mustInclude, runHook(bash(c.command), mkdtempSync(join(tmpdir(), 'guard-'))));
}

// The pinned demo. A real server changing its tools cannot be arranged on a
// schedule, so the pin is altered instead, the way a change would leave it:
// one tool's hash differs and one pinned tool is gone. The re-read and the
// comparison are the real ones, against the live demo server.
const DEMO = 'https://lazaretto.dev/demo/mcp';
const home = mkdtempSync(join(tmpdir(), 'guard-pins-'));
const pinsFile = join(home, 'lazaretto', 'pins.json');
const added = runHook(bash(`claude mcp add --transport http lazaretto-demo ${DEMO}`), home);
let pin = null;
let mode = 0;
try {
  pin = JSON.parse(readFileSync(pinsFile, 'utf8')).servers[DEMO];
  mode = statSync(pinsFile).mode & 0o777;
} catch {
  pin = null;
}
const tools = pin ? Object.keys(pin.tools) : [];
const pinned = pin !== null && /^[0-9a-f]{64}$/.test(pin.sha256) && tools.length > 0 && pin.name === 'lazaretto-demo' && mode === 0o600;
record('pinned demo: the add asks and pins the tools (0600)', 'ask', 'mcp.directive_block', added, pinned);

if (pinned) {
  const edited = tools[0];
  const doc = JSON.parse(readFileSync(pinsFile, 'utf8'));
  const p = doc.servers[DEMO];
  p.sha256 = '0'.repeat(64);
  p.tools[edited] = '0'.repeat(64);
  p.tools.retired_tool = '1'.repeat(64);
  p.checked_at = new Date(Date.now() - 2 * 86_400_000).toISOString();
  writeFileSync(pinsFile, JSON.stringify(doc));

  const start = runHook({ hook_event_name: 'SessionStart', source: 'startup' }, home);
  record('pinned demo: a changed pin is named at session start', 'message', `changed: ${edited}`, start, start.text.includes('removed: retired_tool'));
  const call = runHook({ hook_event_name: 'PreToolUse', tool_name: `mcp__lazaretto-demo__${edited}`, tool_input: {} }, home);
  record('pinned demo: the first call to its tools asks', 'ask', `changed: ${edited}`, call);
  record('pinned demo: asked once, the next call is silent', 'silent', null, runHook({ hook_event_name: 'PreToolUse', tool_name: `mcp__lazaretto-demo__${edited}`, tool_input: {} }, home));

  const again = JSON.parse(readFileSync(pinsFile, 'utf8'));
  again.servers[DEMO].checked_at = new Date(Date.now() - 2 * 86_400_000).toISOString();
  writeFileSync(pinsFile, JSON.stringify(again));
  record('pinned demo: an unchanged re-read is silent', 'silent', null, runHook({ hook_event_name: 'SessionStart', source: 'startup' }, home));
} else {
  rows.push('| pinned demo: change, ask, re-read | not run | no pin | | FAIL |');
}

const report = rows.join('\n');
console.log(report);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### lazaretto-guard against the live service\n\n${report}\n`);
process.exit(failed === 0 ? 0 : 1);
