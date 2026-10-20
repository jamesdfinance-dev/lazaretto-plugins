/**
 * The real hook against the live service, the way Claude Code calls it.
 *
 * Run daily by .github/workflows/guard-live-check.yml from a fresh machine:
 * it gets its own free key, then feeds the hook the exact PreToolUse input
 * Claude Code sends for four commands and checks what comes back. Labelled
 * `+ci`, so the service never counts this as someone using the plugin.
 *
 *   node plugins/lazaretto-guard/test/live/live-check.mjs
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, appendFileSync } from 'node:fs';
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

const rows = ['| case | expected | got | time | result |', '|---|---|---|---|---|'];
let failed = 0;
for (const c of cases) {
  const input = JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: c.command } });
  const started = Date.now();
  const r = spawnSync(process.execPath, [HOOK], {
    input,
    encoding: 'utf8',
    timeout: 9000,
    env: { PATH: process.env.PATH, XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), 'guard-')), LAZARETTO_API_KEY: key, LAZARETTO_GUARD_API: ORIGIN, LAZARETTO_GUARD_CLIENT_SUFFIX: SUFFIX },
  });
  const ms = Date.now() - started;
  let got = 'silent';
  let reason = '';
  if (r.stdout.trim() !== '') {
    try {
      const out = JSON.parse(r.stdout).hookSpecificOutput;
      got = out.permissionDecision;
      reason = out.permissionDecisionReason ?? '';
    } catch {
      got = 'unreadable output';
    }
  }
  const ok = r.status === 0 && got === c.expect && (!c.mustInclude || reason.includes(c.mustInclude));
  if (!ok) failed += 1;
  rows.push(`| ${c.name} | ${c.expect}${c.mustInclude ? ` (${c.mustInclude})` : ''} | ${got} | ${ms} ms | ${ok ? 'pass' : 'FAIL'} |`);
}

const report = rows.join('\n');
console.log(report);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### lazaretto-guard against the live service\n\n${report}\n`);
process.exit(failed === 0 ? 0 : 1);
