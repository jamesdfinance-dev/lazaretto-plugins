import test from 'node:test';
import assert from 'node:assert/strict';
import { decide, settingsFromEnv, buildReason, isMcpConfigPath } from '../lib/decide.mjs';
import { readAnswer } from '../lib/api.mjs';
import { startStub, hitText } from './stub-api.mjs';

const bashInput = (command) => ({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });

/** Settings pointed at a stub, with the timings tests need. */
const settingsFor = (origin, overrides = {}) => ({
  ...settingsFromEnv({}),
  origin,
  path: '/check',
  timeoutMs: 800,
  budgetMs: 1500,
  ...overrides,
});

test('a clean install says nothing', async () => {
  const stub = await startStub({ behaviour: 'clean' });
  try {
    const out = await decide(bashInput('npm install chalk@5.6.1'), { settings: settingsFor(stub.origin) });
    assert.equal(out, null);
    assert.equal(stub.received.length, 1);
    assert.deepEqual(stub.received[0].body, { packages: ['chalk@5.6.1'] });
  } finally {
    await stub.close();
  }
});

test('only names and versions leave the machine', async () => {
  const stub = await startStub({ behaviour: 'clean' });
  try {
    await decide(bashInput('cd /Users/someone/secret-project && npm install chalk@5.6.1 --registry https://internal.example.com'), {
      settings: settingsFor(stub.origin),
      clientTag: 'lazaretto-guard/0.1.0',
    });
    const sent = stub.received[0];
    assert.deepEqual(Object.keys(sent.body), ['packages']);
    assert.deepEqual(sent.body.packages, ['chalk@5.6.1']);
    // Nothing about the command, the path or the registry is anywhere in the body.
    assert.ok(!sent.raw.includes('secret-project'));
    assert.ok(!sent.raw.includes('internal.example.com'));
    assert.ok(!sent.raw.includes('registry'));
    // The client string is stable and carries no identity.
    assert.equal(sent.headers['user-agent'], 'lazaretto-guard/0.1.0');
    assert.equal(sent.headers['x-api-key'], undefined);
    assert.equal(sent.headers.authorization, undefined);
  } finally {
    await stub.close();
  }
});

test('a known malicious version asks, with the evidence', async () => {
  const stub = await startStub({
    behaviour: 'hit',
    hits: [{ ref: 'chalk@5.6.1', ids: ['GHSA-m99c-2xx9-4wvg', 'MAL-2025-4222'] }],
  });
  try {
    const out = await decide(bashInput('npm install chalk@5.6.1 lodash@4.17.21'), { settings: settingsFor(stub.origin) });
    assert.ok(out !== null);
    assert.equal(out.hookSpecificOutput.hookEventName, 'PreToolUse');
    assert.equal(out.hookSpecificOutput.permissionDecision, 'ask');
    const reason = out.hookSpecificOutput.permissionDecisionReason;
    assert.match(reason, /chalk@5\.6\.1/);
    assert.match(reason, /GHSA-m99c-2xx9-4wvg/);
    assert.match(reason, /MAL-2025-4222/);
    assert.match(reason, /osv\.dev/);
    assert.match(reason, /via npm install/);
  } finally {
    await stub.close();
  }
});

test('the decision is never deny, and never mentions paying', async () => {
  const stub = await startStub({ behaviour: 'hit', hits: [{ ref: 'evil@1.0.0', ids: ['MAL-2026-1'] }] });
  try {
    const out = await decide(bashInput('npm i evil@1.0.0'), { settings: settingsFor(stub.origin) });
    const text = JSON.stringify(out);
    assert.equal(out.hookSpecificOutput.permissionDecision, 'ask');
    assert.ok(!text.includes('deny'));
    for (const word of ['pay', 'price', 'credit', 'upgrade to', 'trial', '$', 'buy', 'subscribe']) {
      assert.ok(!text.toLowerCase().includes(word.toLowerCase()), `reason mentions ${word}`);
    }
    // And no claim we are not entitled to make.
    for (const word of ['safe', 'guaranteed', 'secure', 'clean bill']) {
      assert.ok(!text.toLowerCase().includes(word), `reason claims ${word}`);
    }
  } finally {
    await stub.close();
  }
});

test('an mcp server add is checked like any other install', async () => {
  const stub = await startStub({
    behaviour: 'hit',
    hits: [{ ref: '@evil/mcp-server@2.0.1', ids: ['MAL-2026-9001'] }],
  });
  try {
    const out = await decide(bashInput('claude mcp add evil -- npx -y @evil/mcp-server@2.0.1'), {
      settings: settingsFor(stub.origin),
    });
    assert.deepEqual(stub.received[0].body, { packages: ['@evil/mcp-server@2.0.1'] });
    assert.equal(out.hookSpecificOutput.permissionDecision, 'ask');
    assert.match(out.hookSpecificOutput.permissionDecisionReason, /via claude mcp add/);
  } finally {
    await stub.close();
  }
});

test('an mcp server written into .mcp.json is checked too', async () => {
  const stub = await startStub({ behaviour: 'hit', hits: [{ ref: 'weather-mcp@1.4.0', ids: ['MAL-2026-77'] }] });
  try {
    const out = await decide(
      {
        hook_event_name: 'PreToolUse',
        tool_name: 'Write',
        tool_input: {
          file_path: '/work/project/.mcp.json',
          content: JSON.stringify({ mcpServers: { weather: { command: 'npx', args: ['-y', 'weather-mcp@1.4.0'] } } }),
        },
      },
      { settings: settingsFor(stub.origin) },
    );
    assert.equal(out.hookSpecificOutput.permissionDecision, 'ask');
  } finally {
    await stub.close();
  }
});

test('writing an ordinary file is not our business', async () => {
  const stub = await startStub({ behaviour: 'hit', hits: [{ ref: 'weather-mcp@1.4.0', ids: ['MAL-2026-77'] }] });
  try {
    const out = await decide(
      {
        tool_name: 'Write',
        tool_input: { file_path: '/work/project/README.md', content: 'install weather-mcp@1.4.0 to get started' },
      },
      { settings: settingsFor(stub.origin) },
    );
    assert.equal(out, null);
    assert.equal(stub.received.length, 0);
  } finally {
    await stub.close();
  }
});

test('an unparseable command says nothing and calls nothing', async () => {
  const stub = await startStub({ behaviour: 'hit', hits: [{ ref: 'chalk@5.6.1', ids: ['MAL-1'] }] });
  try {
    for (const command of ['npm install $(cat list)', 'npm install "unterminated', 'npm install chalk', '']) {
      const out = await decide(bashInput(command), { settings: settingsFor(stub.origin) });
      assert.equal(out, null, command);
    }
    assert.equal(stub.received.length, 0);
  } finally {
    await stub.close();
  }
});

test('a broken hook input says nothing', async () => {
  for (const input of [null, undefined, {}, { tool_name: 'Bash' }, { tool_name: 'Bash', tool_input: {} }, 'not an object']) {
    assert.equal(await decide(input, { settings: settingsFor('http://127.0.0.1:1') }), null);
  }
});

test('the api being down or rate limited says nothing', async () => {
  for (const behaviour of ['error', 'limit']) {
    const stub = await startStub({ behaviour });
    try {
      const out = await decide(bashInput('npm i chalk@5.6.1'), { settings: settingsFor(stub.origin) });
      assert.equal(out, null, behaviour);
    } finally {
      await stub.close();
    }
  }
});

test('nothing listening at all says nothing, quickly', async () => {
  const started = Date.now();
  const out = await decide(bashInput('npm i chalk@5.6.1'), { settings: settingsFor('http://127.0.0.1:1') });
  assert.equal(out, null);
  assert.ok(Date.now() - started < 1000, 'a refused connection should not cost a second');
});

test('a slow api is abandoned inside the timeout', async () => {
  const stub = await startStub({ behaviour: 'hit', hits: [{ ref: 'chalk@5.6.1', ids: ['MAL-1'] }], delayMs: 5000 });
  try {
    const started = Date.now();
    const out = await decide(bashInput('npm i chalk@5.6.1'), { settings: settingsFor(stub.origin, { timeoutMs: 300 }) });
    const took = Date.now() - started;
    assert.equal(out, null);
    assert.ok(took < 1200, `gave up in ${took}ms`);
  } finally {
    await stub.close();
  }
});

test('offline and hash modes send nothing at all', async () => {
  const stub = await startStub({ behaviour: 'hit', hits: [{ ref: 'chalk@5.6.1', ids: ['MAL-1'] }] });
  try {
    for (const mode of ['offline', 'hash']) {
      const settings = settingsFromEnv({ LAZARETTO_GUARD_MODE: mode, LAZARETTO_GUARD_API: stub.origin });
      const out = await decide(bashInput('npm i chalk@5.6.1'), { settings });
      assert.equal(out, null, mode);
    }
    const off = settingsFromEnv({ LAZARETTO_GUARD_DISABLE: '1', LAZARETTO_GUARD_API: stub.origin });
    assert.equal(await decide(bashInput('npm i chalk@5.6.1'), { settings: off }), null);
    assert.equal(stub.received.length, 0);
  } finally {
    await stub.close();
  }
});

test('a json answer is read as well as a text one', () => {
  const specs = [{ name: 'chalk', version: '5.6.1' }];
  const json = JSON.stringify({ malicious: [{ name: 'chalk', version: '5.6.1', ids: ['MAL-1'] }] });
  assert.deepEqual(readAnswer(json, specs), [{ name: 'chalk', version: '5.6.1', ids: ['MAL-1'] }]);
});

test('a long package name whose columns collide is still read correctly', () => {
  // The real route pads to at most 46 columns, so a longer ref runs straight
  // into its ids with no gap. Reading by layout would get this wrong.
  const ref = '@a-very-long-scope-name/and-a-long-package-name@1.0.0';
  const specs = [{ name: '@a-very-long-scope-name/and-a-long-package-name', version: '1.0.0' }];
  const text = hitText(1, [{ ref, ids: ['MAL-2026-5'] }]);
  assert.ok(text.includes(`${ref}MAL-2026-5`), 'the fixture should reproduce the collision');
  assert.deepEqual(readAnswer(text, specs), [
    { name: '@a-very-long-scope-name/and-a-long-package-name', version: '1.0.0', ids: ['MAL-2026-5'] },
  ]);
});

test('a shorter version does not match the line for a longer one', () => {
  // chalk@5.6.1 is a prefix of chalk@5.6.10. A prefix test reports the clean
  // package as a hit and reads the leftover digit as an advisory id.
  const text = hitText(1, [{ ref: 'chalk@5.6.10', ids: ['MAL-2026-7'] }]);
  assert.deepEqual(readAnswer(text, [{ name: 'chalk', version: '5.6.1' }]), []);
  // The other direction: the ref that is actually on the line still matches.
  assert.deepEqual(readAnswer(text, [{ name: 'chalk', version: '5.6.10' }]), [
    { name: 'chalk', version: '5.6.10', ids: ['MAL-2026-7'] },
  ]);
  // And a prerelease of a version that is listed is a different package.
  const pre = hitText(1, [{ ref: 'chalk@5.6.1-rc.1', ids: ['MAL-2026-8'] }]);
  assert.deepEqual(readAnswer(pre, [{ name: 'chalk', version: '5.6.1' }]), []);
  assert.deepEqual(readAnswer(pre, [{ name: 'chalk', version: '5.6.1-rc.1' }]), [
    { name: 'chalk', version: '5.6.1-rc.1', ids: ['MAL-2026-8'] },
  ]);
});

test('a hit stays a hit when both versions are listed together', () => {
  const text = hitText(2, [
    { ref: 'chalk@5.6.1', ids: ['MAL-2026-1'] },
    { ref: 'chalk@5.6.10', ids: ['MAL-2026-2'] },
  ]);
  assert.deepEqual(readAnswer(text, [{ name: 'chalk', version: '5.6.1' }]), [
    { name: 'chalk', version: '5.6.1', ids: ['MAL-2026-1'] },
  ]);
  assert.deepEqual(readAnswer(text, [{ name: 'chalk', version: '5.6.10' }]), [
    { name: 'chalk', version: '5.6.10', ids: ['MAL-2026-2'] },
  ]);
});

test('buildReason counts what it checked and what matched', () => {
  const reason = buildReason(
    [{ name: 'a', version: '1.0.0', ids: ['MAL-1'] }],
    [
      { name: 'a', version: '1.0.0', via: 'npm install' },
      { name: 'b', version: '2.0.0', via: 'npm install' },
    ],
  );
  assert.match(reason, /1 of 2 pinned packages/);
  assert.match(reason, /says nothing about the packages that did not match/);
});

test('mcp config paths are recognised and ordinary ones are not', () => {
  assert.equal(isMcpConfigPath('/a/b/.mcp.json'), true);
  assert.equal(isMcpConfigPath('/a/.claude/settings.json'), true);
  assert.equal(isMcpConfigPath('/a/.cursor/mcp.json'), true);
  assert.equal(isMcpConfigPath('/a/package.json'), false);
  assert.equal(isMcpConfigPath(''), false);
});
