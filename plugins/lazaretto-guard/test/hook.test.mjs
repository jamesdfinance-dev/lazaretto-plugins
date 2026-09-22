/**
 * The hook as Claude Code actually runs it: a separate process, JSON on stdin,
 * JSON or nothing on stdout, an exit code.
 *
 * The point of this file is the last three tests. hooks.json declares a 2
 * second timeout, so anything slower than that is a stalled install. These
 * prove the process gets out on its own, before Claude Code has to kill it,
 * even when the API hangs forever and even when stdin never closes.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startStub } from './stub-api.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOOK = path.join(HERE, '..', 'hooks', 'guard.mjs');

/** The timeout hooks.json declares, in milliseconds. Nothing may exceed it. */
const HOOK_TIMEOUT_MS = 2000;

/**
 * Run the hook the way Claude Code does.
 * `closeStdin: false` leaves the pipe open, which is the pathological case.
 */
function runHook({ input, env = {}, closeStdin = true }) {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(process.execPath, [HOOK], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => {
      stdout += c;
    });
    child.stderr.on('data', (c) => {
      stderr += c;
    });
    child.on('close', (code, signal) => {
      resolve({ code, signal, stdout, stderr, ms: Date.now() - started });
    });
    child.stdin.on('error', () => {});
    child.stdin.write(typeof input === 'string' ? input : JSON.stringify(input));
    if (closeStdin) child.stdin.end();
  });
}

const bashInput = (command) => ({
  session_id: 'test',
  hook_event_name: 'PreToolUse',
  tool_name: 'Bash',
  tool_input: { command },
});

test('a clean install: nothing on stdout, exit 0', async () => {
  const stub = await startStub({ behaviour: 'clean' });
  try {
    const r = await runHook({
      input: bashInput('npm install chalk@5.6.1'),
      env: { LAZARETTO_GUARD_API: stub.origin },
    });
    assert.equal(r.stdout, '');
    assert.equal(r.code, 0);
    assert.equal(r.stderr, '');
  } finally {
    await stub.close();
  }
});

test('a known malicious version: one ask payload, exit 0', async () => {
  const stub = await startStub({
    behaviour: 'hit',
    hits: [{ ref: 'chalk@5.6.1', ids: ['GHSA-m99c-2xx9-4wvg'] }],
  });
  try {
    const r = await runHook({
      input: bashInput('npm install chalk@5.6.1'),
      env: { LAZARETTO_GUARD_API: stub.origin },
    });
    assert.equal(r.code, 0);
    const payload = JSON.parse(r.stdout);
    assert.equal(payload.hookSpecificOutput.hookEventName, 'PreToolUse');
    assert.equal(payload.hookSpecificOutput.permissionDecision, 'ask');
    assert.match(payload.hookSpecificOutput.permissionDecisionReason, /GHSA-m99c-2xx9-4wvg/);
  } finally {
    await stub.close();
  }
});

test('an mcp server add reaches the api as a package identity', async () => {
  const stub = await startStub({ behaviour: 'clean' });
  try {
    const r = await runHook({
      input: bashInput('claude mcp add fs -- npx -y @modelcontextprotocol/server-filesystem@0.6.2 /tmp'),
      env: { LAZARETTO_GUARD_API: stub.origin },
    });
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.deepEqual(stub.received[0].body, { packages: ['@modelcontextprotocol/server-filesystem@0.6.2'] });
  } finally {
    await stub.close();
  }
});

test('an unparseable command: silent, exit 0, nothing sent', async () => {
  const stub = await startStub({ behaviour: 'hit', hits: [{ ref: 'chalk@5.6.1', ids: ['MAL-1'] }] });
  try {
    for (const command of ['npm install $(cat list.txt)', 'npm install "unterminated', 'ls -la']) {
      const r = await runHook({ input: bashInput(command), env: { LAZARETTO_GUARD_API: stub.origin } });
      assert.equal(r.stdout, '', command);
      assert.equal(r.code, 0, command);
    }
    assert.equal(stub.received.length, 0);
  } finally {
    await stub.close();
  }
});

test('garbage on stdin: silent, exit 0', async () => {
  for (const raw of ['', 'not json', '{"tool_name":', '[]', 'null']) {
    const r = await runHook({ input: raw, env: { LAZARETTO_GUARD_API: 'http://127.0.0.1:1' } });
    assert.equal(r.stdout, '', raw);
    assert.equal(r.code, 0, raw);
  }
});

test('the hook never exits 2, whatever happens', async () => {
  const stub = await startStub({ behaviour: 'error' });
  try {
    const cases = [
      { input: bashInput('npm i chalk@5.6.1'), env: { LAZARETTO_GUARD_API: stub.origin } },
      { input: bashInput('npm i chalk@5.6.1'), env: { LAZARETTO_GUARD_API: 'http://127.0.0.1:1' } },
      { input: bashInput('npm i chalk@5.6.1'), env: { LAZARETTO_GUARD_API: 'not-a-url' } },
      { input: 'garbage', env: {} },
      { input: bashInput('rm -rf /'), env: { LAZARETTO_GUARD_API: stub.origin } },
    ];
    for (const c of cases) {
      const r = await runHook(c);
      assert.notEqual(r.code, 2, JSON.stringify(c.input).slice(0, 60));
      assert.equal(r.code, 0);
    }
  } finally {
    await stub.close();
  }
});

test('an api that never answers cannot hang the install', async () => {
  const stub = await startStub({ behaviour: 'hang' });
  try {
    const r = await runHook({
      input: bashInput('npm install chalk@5.6.1'),
      env: { LAZARETTO_GUARD_API: stub.origin },
    });
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.ok(
      r.ms < HOOK_TIMEOUT_MS,
      `hook took ${r.ms}ms, which is not inside the ${HOOK_TIMEOUT_MS}ms declared in hooks.json`,
    );
    // And with room to spare, so a loaded machine does not turn this into a
    // timeout Claude Code has to report.
    assert.ok(r.ms < HOOK_TIMEOUT_MS - 150, `hook took ${r.ms}ms, leaving too little margin`);
  } finally {
    await stub.close();
  }
});

test('a hanging api plus a tiny budget still exits well inside the timeout', async () => {
  const stub = await startStub({ behaviour: 'hang' });
  try {
    const r = await runHook({
      input: bashInput('npm install chalk@5.6.1'),
      env: { LAZARETTO_GUARD_API: stub.origin, LAZARETTO_GUARD_TIMEOUT_MS: '200', LAZARETTO_GUARD_BUDGET_MS: '400' },
    });
    assert.equal(r.code, 0);
    assert.ok(r.ms < 1000, `hook took ${r.ms}ms`);
  } finally {
    await stub.close();
  }
});

test('stdin that never closes is abandoned by the watchdog', async () => {
  const r = await runHook({
    input: '{"tool_name":"Bash","tool_input":{"command":"npm i chalk@5.6.1"',
    env: { LAZARETTO_GUARD_BUDGET_MS: '300', LAZARETTO_GUARD_API: 'http://127.0.0.1:1' },
    closeStdin: false,
  });
  assert.equal(r.code, 0);
  assert.equal(r.stdout, '');
  assert.ok(r.ms < HOOK_TIMEOUT_MS, `hook took ${r.ms}ms with stdin held open`);
});

test('offline mode never opens a socket', async () => {
  const stub = await startStub({ behaviour: 'hit', hits: [{ ref: 'chalk@5.6.1', ids: ['MAL-1'] }] });
  try {
    const r = await runHook({
      input: bashInput('npm install chalk@5.6.1'),
      env: { LAZARETTO_GUARD_API: stub.origin, LAZARETTO_GUARD_MODE: 'offline' },
    });
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.equal(stub.received.length, 0);
  } finally {
    await stub.close();
  }
});
