/**
 * Turn a command into the list of pinned package identities it is about to put
 * on disk.
 *
 * Two rules run through everything here:
 *
 *  1. Only exactly pinned versions are returned. A range like ^5.0.0 or a tag
 *     like `latest` has no definitive answer, because the compromised release
 *     usually sits between clean ones. If a command has no pinned version, this
 *     returns nothing and the hook stays silent.
 *  2. Anything ambiguous returns nothing. Silence is the correct output far
 *     more often than a guess.
 */
import { tokenize } from './tokenize.mjs';

/** Exact semver, the only thing the advisory feed can answer about. */
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/** An npm package name, scoped or not. Permissive about case for old names. */
const PACKAGE_NAME = /^(?:@[A-Za-z0-9][A-Za-z0-9._-]*\/)?[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Protocol prefixes that mean "this is not a registry identity". */
const NON_REGISTRY = /^(?:file|link|workspace|git|git\+ssh|git\+https|github|gitlab|bitbucket|npm|jsr|portal|catalog|patch|http|https):/i;

/** Package managers whose install subcommands we read. */
const INSTALL_SUBCOMMANDS = {
  npm: new Set(['install', 'i', 'add', 'ci', 'in', 'ins', 'inst', 'instal', 'isnt', 'isntall', 'install-test', 'it']),
  pnpm: new Set(['install', 'i', 'add']),
  yarn: new Set(['install', 'add']),
  bun: new Set(['install', 'i', 'add', 'a']),
};

/** Subcommands that download and run a package without installing it. */
const RUNNER_SUBCOMMANDS = {
  pnpm: new Set(['dlx', 'exec']),
  yarn: new Set(['dlx']),
  bun: new Set(['x']),
  npm: new Set(['exec']),
};

/** Bare runner binaries. */
const RUNNERS = new Set(['npx', 'bunx', 'pnpx']);

/** Prefixes to step over before the real command starts. */
const PREFIXES = new Set(['sudo', 'env', 'command', 'time', 'nice', 'exec', 'doas', 'setsid', 'stdbuf']);

/**
 * Flags that swallow the next token, for install subcommands. Listed so a
 * value like `--workspace foo` is never mistaken for a package spec. Flags not
 * on this list are skipped on their own, which is the quieter default because a
 * spec must still pass the pinned-version test to be returned.
 */
const INSTALL_VALUE_FLAGS = new Set([
  '--prefix', '--registry', '--workspace', '-w', '--omit', '--include', '--cache',
  '--userconfig', '--globalconfig', '--tag', '--loglevel', '--before', '--filter',
  '-F', '-C', '--cwd', '--dir', '--config', '--store-dir', '--lockfile-dir',
]);

/** Same idea for runners, minus the ones that really do carry a package spec. */
const RUNNER_VALUE_FLAGS = new Set([
  '--registry', '--cache', '--shell', '--node-arg', '-n', '--userconfig', '--call', '-c',
]);

/** Runner flags whose value IS a package spec. */
const RUNNER_PACKAGE_FLAGS = new Set(['--package', '-p']);

/** How deep a `claude mcp add ... -- <command>` chain we will follow. */
const MAX_DEPTH = 3;

/** Most specs we will ever report on one command. */
const MAX_TARGETS = 50;

/**
 * Parse one token into `{ name, version }`, or null when it is not an exactly
 * pinned registry package.
 */
export function parseSpec(token) {
  if (typeof token !== 'string' || token === '') return null;
  if (token.startsWith('-')) return null;
  if (/^[.~/]/.test(token)) return null;
  if (token.includes('://')) return null;
  if (NON_REGISTRY.test(token)) return null;
  const at = token.lastIndexOf('@');
  if (at <= 0) return null;
  const name = token.slice(0, at);
  const version = token.slice(at + 1);
  if (!PACKAGE_NAME.test(name)) return null;
  if (!EXACT_VERSION.test(version)) return null;
  return { name, version };
}

/** Strip a directory prefix so `/usr/local/bin/npm` reads as `npm`. */
function binaryName(token) {
  if (typeof token !== 'string') return '';
  const slash = token.lastIndexOf('/');
  return slash === -1 ? token : token.slice(slash + 1);
}

/** Drop `VAR=value` and wrapper binaries from the front of a segment. */
function stripPrefixes(tokens) {
  let i = 0;
  while (i < tokens.length) {
    const t = tokens[i];
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
      i += 1;
      continue;
    }
    if (PREFIXES.has(binaryName(t))) {
      i += 1;
      continue;
    }
    break;
  }
  return tokens.slice(i);
}

function addTarget(out, spec, via) {
  if (spec === null) return;
  if (out.length >= MAX_TARGETS) return;
  const ref = `${spec.name}@${spec.version}`;
  if (out.some((t) => `${t.name}@${t.version}` === ref)) return;
  out.push({ name: spec.name, version: spec.version, via });
}

/** Read the argument list of an install subcommand. */
function collectFromInstall(tokens, out, via) {
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t.startsWith('-')) {
      if (INSTALL_VALUE_FLAGS.has(t)) i += 1;
      continue;
    }
    addTarget(out, parseSpec(t), via);
  }
}

/** Read the argument list of a runner (`npx`, `pnpm dlx`, `bunx`). */
function collectFromRunner(tokens, out, via) {
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t.startsWith('-')) {
      if (RUNNER_PACKAGE_FLAGS.has(t)) {
        addTarget(out, parseSpec(tokens[i + 1]), via);
        i += 1;
        continue;
      }
      const eq = t.indexOf('=');
      if (eq !== -1 && RUNNER_PACKAGE_FLAGS.has(t.slice(0, eq))) {
        addTarget(out, parseSpec(t.slice(eq + 1)), via);
        continue;
      }
      if (RUNNER_VALUE_FLAGS.has(t)) i += 1;
      continue;
    }
    // The first bare token is what gets fetched and run; everything after it is
    // that program's own arguments, so stop.
    addTarget(out, parseSpec(t), via);
    return;
  }
}

/**
 * `claude mcp add` in all the shapes people write it. The package identity of
 * an MCP server is whatever its stdio command fetches, so we follow the command
 * after `--`, or the JSON config of `claude mcp add-json`.
 */
function collectFromMcpAdd(tokens, out, depth) {
  const via = 'claude mcp add';
  const sep = tokens.indexOf('--');
  if (sep !== -1) {
    collectSegment(tokens.slice(sep + 1), out, depth + 1, via);
    return;
  }
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t.startsWith('{')) {
      let config = null;
      try {
        config = JSON.parse(t);
      } catch {
        config = null;
      }
      if (config && typeof config === 'object') {
        collectFromMcpConfigEntry(config, out, depth + 1, via);
      }
      continue;
    }
    if (RUNNERS.has(binaryName(t)) || INSTALL_SUBCOMMANDS[binaryName(t)] !== undefined) {
      collectSegment(tokens.slice(i), out, depth + 1, via);
      return;
    }
  }
}

/** One `{ command, args }` entry from an MCP server config. */
export function collectFromMcpConfigEntry(entry, out, depth = 1, via = 'mcp server config') {
  if (!entry || typeof entry !== 'object') return;
  const command = typeof entry.command === 'string' ? entry.command : null;
  const args = Array.isArray(entry.args) ? entry.args.filter((a) => typeof a === 'string') : [];
  if (command === null && args.length === 0) return;
  collectSegment([command ?? '', ...args].filter((t) => t !== ''), out, depth, via);
}

/** Dispatch one segment of tokens to whichever collector fits its head. */
function collectSegment(rawTokens, out, depth, viaOverride) {
  if (depth > MAX_DEPTH) return;
  const tokens = stripPrefixes(rawTokens);
  if (tokens.length === 0) return;
  const head = binaryName(tokens[0]);

  if (RUNNERS.has(head)) {
    collectFromRunner(tokens.slice(1), out, viaOverride ?? head);
    return;
  }

  if (head === 'claude') {
    if (tokens[1] === 'mcp' && (tokens[2] === 'add' || tokens[2] === 'add-json')) {
      collectFromMcpAdd(tokens.slice(3), out, depth);
    }
    return;
  }

  const installers = INSTALL_SUBCOMMANDS[head];
  const runners = RUNNER_SUBCOMMANDS[head];
  if (installers === undefined && runners === undefined) return;

  // Find the subcommand: the first token that is not a flag.
  let sub = null;
  let rest = [];
  for (let i = 1; i < tokens.length; i += 1) {
    if (tokens[i].startsWith('-')) continue;
    sub = tokens[i];
    rest = tokens.slice(i + 1);
    break;
  }
  if (sub === null) return;

  if (runners !== undefined && runners.has(sub)) {
    collectFromRunner(rest, out, viaOverride ?? `${head} ${sub}`);
    return;
  }
  if (installers !== undefined && installers.has(sub)) {
    collectFromInstall(rest, out, viaOverride ?? `${head} ${sub}`);
  }
}

/**
 * The public entry point. Returns `{ ok, targets }`, where `ok: false` means
 * the command could not be read confidently and the caller must stay silent.
 */
export function parseCommand(command) {
  const { ok, segments } = tokenize(command);
  if (!ok) return { ok: false, targets: [] };
  const out = [];
  for (const segment of segments) collectSegment(segment, out, 0, undefined);
  return { ok: true, targets: out };
}

/**
 * The same question asked of an MCP server config file rather than a command,
 * because plenty of servers are added by writing `.mcp.json` instead of running
 * `claude mcp add`.
 */
export function parseMcpConfigText(text) {
  const out = [];
  if (typeof text !== 'string' || text === '') return { ok: true, targets: out };
  let doc = null;
  try {
    doc = JSON.parse(text);
  } catch {
    doc = null;
  }
  if (doc && typeof doc === 'object') {
    const servers = doc.mcpServers && typeof doc.mcpServers === 'object' ? doc.mcpServers : doc;
    for (const entry of Object.values(servers)) collectFromMcpConfigEntry(entry, out, 1, 'mcp server config');
    if (out.length > 0) return { ok: true, targets: out };
  }
  // An Edit hands us a fragment, not a document. Fall back to reading quoted
  // tokens, which is what a server's `args` array is made of.
  for (const m of text.matchAll(/"([^"\s]{1,214})"/g)) {
    addTarget(out, parseSpec(m[1]), 'mcp server config');
  }
  return { ok: true, targets: out };
}
