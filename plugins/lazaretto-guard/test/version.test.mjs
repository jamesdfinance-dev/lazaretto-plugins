/**
 * The version is declared once, in the plugin manifest, and copied nowhere.
 *
 * The client tag is the only version string that leaves the machine, so the
 * first test is the one that matters: run the hook the way Claude Code does and
 * read the tag the API would have seen. The rest hold the manifests that cannot
 * import anything, package.json and the marketplace entry, to the same number,
 * and catch a hardcoded tag creeping back into the two entry points.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startStub } from './stub-api.mjs';
import { CLIENT_TAG, VERSION } from '../lib/version.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..');
const HOOK = path.join(ROOT, 'hooks', 'guard.mjs');

const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
const PLUGIN_VERSION = readJson(path.join(ROOT, '.claude-plugin', 'plugin.json')).version;

test('the tag the hook puts on the wire carries the plugin.json version', async () => {
  const stub = await startStub({ behaviour: 'clean' });
  try {
    await new Promise((resolve) => {
      const child = spawn(process.execPath, [HOOK], {
        env: { ...process.env, LAZARETTO_GUARD_API: stub.origin },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      child.on('close', resolve);
      child.stdin.on('error', () => {});
      child.stdin.end(
        JSON.stringify({
          hook_event_name: 'PreToolUse',
          tool_name: 'Bash',
          tool_input: { command: 'npm install chalk@5.6.1' },
        }),
      );
    });

    assert.equal(stub.received.length, 1);
    const expected = `lazaretto-guard/${PLUGIN_VERSION}`;
    assert.equal(stub.received[0].headers['x-lazaretto-client'], expected);
    assert.equal(stub.received[0].headers['user-agent'], expected);
  } finally {
    await stub.close();
  }
});

test('the exported tag and version come from the manifest', () => {
  assert.match(PLUGIN_VERSION, /^\d+\.\d+\.\d+/);
  assert.equal(VERSION, PLUGIN_VERSION);
  assert.equal(CLIENT_TAG, `lazaretto-guard/${PLUGIN_VERSION}`);
});

test('package.json agrees with the manifest', () => {
  assert.equal(readJson(path.join(ROOT, 'package.json')).version, PLUGIN_VERSION);
});

test('the marketplace entry agrees with the manifest', (t) => {
  const marketplace = path.join(ROOT, '..', '..', '.claude-plugin', 'marketplace.json');
  if (!existsSync(marketplace)) {
    t.skip('no marketplace.json here, so the plugin is not sitting in its repo');
    return;
  }
  const entry = readJson(marketplace).plugins.find((p) => p.name === 'lazaretto-guard');
  assert.ok(entry, 'no lazaretto-guard entry in marketplace.json');
  assert.equal(entry.version, PLUGIN_VERSION);
});

test('neither entry point hardcodes a version', () => {
  for (const file of [HOOK, path.join(ROOT, 'bin', 'lazaretto-guard.mjs')]) {
    const source = readFileSync(file, 'utf8');
    assert.doesNotMatch(source, /lazaretto-guard\/\$\{?\d|lazaretto-guard\/\d/, `${file} carries its own version`);
  }
});
