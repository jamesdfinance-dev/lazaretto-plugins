import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalArtifactHash, hashPath, verifyInstalled } from '../lib/hash.mjs';

function tempTree(files) {
  const dir = mkdtempSync(path.join(tmpdir(), 'lazaretto-guard-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    mkdirSync(path.dirname(abs), { recursive: true });
    writeFileSync(abs, content);
  }
  return dir;
}

test('a single file hashes to a plain sha256 of its bytes', () => {
  const expected = `sha256:${createHash('sha256').update(Buffer.from('hello', 'utf8')).digest('hex')}`;
  assert.equal(canonicalArtifactHash([{ path: 'a.js', content: 'hello' }]), expected);
});

test('a tree hashes the same whatever order the files arrive in', () => {
  const files = [
    { path: 'a.js', content: 'one' },
    { path: 'b/c.js', content: 'two' },
    { path: 'd.js', content: 'three' },
  ];
  const forward = canonicalArtifactHash(files);
  const backward = canonicalArtifactHash([...files].reverse());
  assert.equal(forward, backward);
});

test('a changed byte changes the hash', () => {
  const a = canonicalArtifactHash([
    { path: 'a.js', content: 'one' },
    { path: 'b.js', content: 'two' },
  ]);
  const b = canonicalArtifactHash([
    { path: 'a.js', content: 'one' },
    { path: 'b.js', content: 'two.' },
  ]);
  assert.notEqual(a, b);
});

test('git and node_modules are not part of what was scanned', () => {
  const withNoise = tempTree({
    'index.js': 'export default 1;\n',
    'node_modules/dep/index.js': 'whatever',
    '.git/HEAD': 'ref: refs/heads/main',
  });
  const clean = tempTree({ 'index.js': 'export default 1;\n' });
  try {
    assert.equal(hashPath(withNoise), hashPath(clean));
  } finally {
    rmSync(withNoise, { recursive: true, force: true });
    rmSync(clean, { recursive: true, force: true });
  }
});

test('verifyInstalled catches drift from the hash the person holds', () => {
  const dir = tempTree({ 'index.js': 'export default 1;\n' });
  try {
    const recorded = hashPath(dir);
    assert.equal(verifyInstalled(dir, recorded).match, true);
    // The bare hex form is accepted too, because that is how people paste it.
    assert.equal(verifyInstalled(dir, recorded.replace('sha256:', '')).match, true);

    writeFileSync(path.join(dir, 'postinstall.js'), 'fetch("http://elsewhere")');
    const after = verifyInstalled(dir, recorded);
    assert.equal(after.match, false);
    assert.match(after.message, /not what you expected/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
