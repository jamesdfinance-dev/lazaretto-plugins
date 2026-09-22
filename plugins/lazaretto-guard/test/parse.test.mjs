import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCommand, parseSpec, parseMcpConfigText } from '../lib/parse.mjs';
import { tokenize } from '../lib/tokenize.mjs';

const refs = (command) => parseCommand(command).targets.map((t) => `${t.name}@${t.version}`);

test('parseSpec takes exact versions and nothing else', () => {
  assert.deepEqual(parseSpec('chalk@5.6.1'), { name: 'chalk', version: '5.6.1' });
  assert.deepEqual(parseSpec('@scope/pkg@1.2.3-beta.1'), { name: '@scope/pkg', version: '1.2.3-beta.1' });
  assert.equal(parseSpec('chalk'), null);
  assert.equal(parseSpec('chalk@^5.0.0'), null);
  assert.equal(parseSpec('chalk@latest'), null);
  assert.equal(parseSpec('chalk@5.x'), null);
  assert.equal(parseSpec('./local-thing@1.0.0'), null);
  assert.equal(parseSpec('file:../pkg@1.0.0'), null);
  assert.equal(parseSpec('https://example.com/p@1.0.0'), null);
  assert.equal(parseSpec('--save-dev'), null);
  assert.equal(parseSpec('@scope'), null);
});

test('npm, pnpm, yarn and bun installs', () => {
  assert.deepEqual(refs('npm install chalk@5.6.1'), ['chalk@5.6.1']);
  assert.deepEqual(refs('npm i --save-dev typescript@5.4.5'), ['typescript@5.4.5']);
  assert.deepEqual(refs('pnpm add @scope/thing@2.0.0'), ['@scope/thing@2.0.0']);
  assert.deepEqual(refs('yarn add left-pad@1.3.0 right-pad@2.0.0'), ['left-pad@1.3.0', 'right-pad@2.0.0']);
  assert.deepEqual(refs('bun add hono@4.6.3'), ['hono@4.6.3']);
  assert.deepEqual(refs('sudo npm install -g pm2@5.4.2'), ['pm2@5.4.2']);
  assert.deepEqual(refs('CI=1 npm install chalk@5.6.1'), ['chalk@5.6.1']);
  assert.deepEqual(refs('/usr/local/bin/npm install chalk@5.6.1'), ['chalk@5.6.1']);
});

test('unpinned installs produce nothing, which is silence', () => {
  assert.deepEqual(refs('npm install'), []);
  assert.deepEqual(refs('npm ci'), []);
  assert.deepEqual(refs('npm install chalk'), []);
  assert.deepEqual(refs('npm install chalk@^5.0.0'), []);
  assert.deepEqual(refs('yarn'), []);
});

test('a value flag is never mistaken for a package', () => {
  assert.deepEqual(refs('npm install --workspace api@1.0.0 chalk@5.6.1'), ['chalk@5.6.1']);
  assert.deepEqual(refs('npm install --registry https://r.example.com chalk@5.6.1'), ['chalk@5.6.1']);
});

test('runners: npx, bunx, pnpm dlx, yarn dlx', () => {
  assert.deepEqual(refs('npx cowsay@1.6.0 hello'), ['cowsay@1.6.0']);
  assert.deepEqual(refs('npx -y @modelcontextprotocol/server-filesystem@0.6.2 /tmp'), [
    '@modelcontextprotocol/server-filesystem@0.6.2',
  ]);
  assert.deepEqual(refs('pnpm dlx tsx@4.19.1 script.ts'), ['tsx@4.19.1']);
  assert.deepEqual(refs('bunx zx@8.1.4'), ['zx@8.1.4']);
  assert.deepEqual(refs('npx --package esbuild@0.23.1 -- esbuild --version'), ['esbuild@0.23.1']);
});

test('arguments after the runner target are that program, not packages', () => {
  assert.deepEqual(refs('npx tsx@4.19.1 build.ts --dep other@1.0.0'), ['tsx@4.19.1']);
});

test('claude mcp add, in the shapes people write it', () => {
  assert.deepEqual(refs('claude mcp add fs -- npx -y @modelcontextprotocol/server-filesystem@0.6.2 /tmp'), [
    '@modelcontextprotocol/server-filesystem@0.6.2',
  ]);
  assert.deepEqual(refs('claude mcp add --transport stdio weather npx -y weather-mcp@1.4.0'), ['weather-mcp@1.4.0']);
  assert.deepEqual(
    refs('claude mcp add-json gh \'{"command":"npx","args":["-y","@foo/gh-mcp@3.1.0"]}\''),
    ['@foo/gh-mcp@3.1.0'],
  );
  assert.deepEqual(refs('claude mcp add remote --transport http https://example.com/mcp'), []);
  assert.deepEqual(refs('claude mcp list'), []);
});

test('the via label says which surface the package came from', () => {
  const [target] = parseCommand('claude mcp add fs -- npx -y srv@1.0.0').targets;
  assert.equal(target.via, 'claude mcp add');
  const [npmTarget] = parseCommand('npm install chalk@5.6.1').targets;
  assert.equal(npmTarget.via, 'npm install');
});

test('chained commands are all read', () => {
  assert.deepEqual(refs('cd /tmp && npm install chalk@5.6.1 && npm test'), ['chalk@5.6.1']);
  assert.deepEqual(refs('npm i a@1.0.0; npm i b@2.0.0'), ['a@1.0.0', 'b@2.0.0']);
});

test('duplicates collapse', () => {
  assert.deepEqual(refs('npm i chalk@5.6.1 chalk@5.6.1'), ['chalk@5.6.1']);
});

test('commands we cannot read confidently are refused, not guessed at', () => {
  assert.equal(parseCommand('npm install "unterminated').ok, false);
  assert.equal(parseCommand('npm install $(cat list.txt)').ok, false);
  assert.equal(parseCommand('npm install `cat list.txt`').ok, false);
  assert.equal(parseCommand('').ok, false);
  assert.equal(parseCommand(null).ok, false);
  assert.equal(parseCommand(undefined).ok, false);
  assert.equal(parseCommand(12345).ok, false);
});

test('a refused command yields no targets at all', () => {
  const result = parseCommand('npm install "unterminated chalk@5.6.1');
  assert.equal(result.ok, false);
  assert.deepEqual(result.targets, []);
});

test('unrelated commands are read fine and yield nothing', () => {
  for (const cmd of ['ls -la', 'git commit -m "npm install chalk@5.6.1"', 'echo hi', 'cargo add serde@1.0.0']) {
    const r = parseCommand(cmd);
    assert.equal(r.ok, true, cmd);
    assert.deepEqual(r.targets, [], cmd);
  }
});

test('quotes are handled', () => {
  assert.deepEqual(refs('npm install "chalk@5.6.1"'), ['chalk@5.6.1']);
  assert.deepEqual(refs("npm install 'chalk@5.6.1'"), ['chalk@5.6.1']);
});

test('tokenize splits on operators and keeps quoted spaces', () => {
  const { ok, segments } = tokenize('echo "a b" && npm i x@1.0.0');
  assert.equal(ok, true);
  assert.deepEqual(segments, [
    ['echo', 'a b'],
    ['npm', 'i', 'x@1.0.0'],
  ]);
});

test('an mcp config file yields the packages its servers fetch', () => {
  const doc = JSON.stringify({
    mcpServers: {
      fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@0.6.2', '/tmp'] },
      remote: { url: 'https://example.com/mcp' },
    },
  });
  assert.deepEqual(
    parseMcpConfigText(doc).targets.map((t) => `${t.name}@${t.version}`),
    ['@modelcontextprotocol/server-filesystem@0.6.2'],
  );
});

test('an edit fragment of an mcp config still yields the package', () => {
  const fragment = '    "args": ["-y", "weather-mcp@1.4.0"],';
  assert.deepEqual(
    parseMcpConfigText(fragment).targets.map((t) => `${t.name}@${t.version}`),
    ['weather-mcp@1.4.0'],
  );
});

test('a long command does not blow up the parser', () => {
  const long = `npm install ${'a@1.0.0 '.repeat(500)}`;
  const r = parseCommand(long);
  assert.equal(r.ok, true);
  assert.ok(r.targets.length <= 50);
});
