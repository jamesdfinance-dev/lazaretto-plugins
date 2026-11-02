/**
 * The remote MCP servers already in Claude Code's own config.
 *
 * The add path only sees a server when the agent adds it. A person typing
 * `claude mcp add` in a terminal, or a server added before this plugin was
 * installed, never passes through a hook, so its tools were never read and
 * never pinned. Reading the config at session start covers both.
 *
 * This reads config files that hold other people's secrets (auth headers,
 * OAuth settings), so it is deliberately narrow. Only `mcpServers` is looked
 * at, and only the URL and name leave this module. An entry with any kind of
 * credential is dropped whole, as is a host that only means something on a
 * private network: our scanner could not reach it, and its name is not ours to
 * learn.
 */
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { shareableUrl } from './mcp-scan.mjs';
import { cleanServerName } from './pins.mjs';

/** Bigger than any real config. A file past this is left unread. */
const MAX_CONFIG_BYTES = 20_000_000;

/** Most servers taken from the config, so a hostile `.mcp.json` stays bounded. */
const MAX_CONFIGURED = 50;

/** Most projects looked through for a server that may have been removed. */
const MAX_PROJECTS = 500;

/** Fields that mean an entry authenticates. Their presence means skip. */
const CREDENTIAL_FIELDS = ['headers', 'headersHelper', 'oauth', 'env'];

/** Endings that never resolve on the public internet. */
const PRIVATE_ENDINGS = new Set(['local', 'localhost', 'internal', 'intranet', 'corp', 'lan', 'home', 'test', 'invalid']);

/** Labels that mark a private network anywhere in a name, as in mcp.internal.acme.com. */
const PRIVATE_LABELS = new Set(['internal', 'intranet', 'corp', 'vpn']);

/** Where Claude Code keeps user and local scope MCP servers. */
export function claudeConfigPath(env = process.env) {
  return join(env.CLAUDE_CONFIG_DIR || env.HOME || homedir(), '.claude.json');
}

function readJson(file) {
  try {
    if (statSync(file).size > MAX_CONFIG_BYTES) return null;
    const doc = JSON.parse(readFileSync(file, 'utf8'));
    return doc && typeof doc === 'object' ? doc : null;
  } catch {
    return null;
  }
}

/** True for an IP literal, a single-label name, a private ending, or a private label anywhere. */
export function isPrivateHost(hostname) {
  const host = hostname.toLowerCase();
  if (!host.includes('.') || host.startsWith('[') || /^[\d.]+$/.test(host)) return true;
  const labels = host.split('.');
  return PRIVATE_ENDINGS.has(labels.at(-1)) || labels.some((label) => PRIVATE_LABELS.has(label));
}

/** The server one config entry names, as `{ url, name }`, or null when it should not be sent. */
function readEntry(name, entry) {
  if (!entry || typeof entry !== 'object') return null;
  if (entry.type !== undefined && entry.type !== 'http' && entry.type !== 'sse') return null;
  if (CREDENTIAL_FIELDS.some((field) => entry[field] !== undefined)) return null;
  // `${VAR}` is expanded by Claude Code at connect time, so this is not the real URL.
  if (typeof entry.url !== 'string' || entry.url.includes('$')) return null;
  const url = shareableUrl(entry.url);
  if (url === null || isPrivateHost(new URL(url).hostname)) return null;
  return { url, name: cleanServerName(name) };
}

const own = (o, k) => (o && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined);

/** A directory and every directory above it. */
function upFrom(dir) {
  const dirs = [dir];
  while (dirname(dirs.at(-1)) !== dirs.at(-1)) dirs.push(dirname(dirs.at(-1)));
  return dirs;
}

function realOrSame(dir) {
  try {
    return realpathSync(dir);
  } catch {
    return dir;
  }
}

/**
 * The folder Claude Code files this directory's local servers under: the root
 * of the git repository it is in, and for a git worktree the main checkout's
 * root. Outside a repository, there is none and the directory itself is used.
 */
function gitProjectRoot(dir) {
  for (const candidate of upFrom(dir)) {
    let stat;
    try {
      stat = statSync(join(candidate, '.git'));
    } catch {
      continue;
    }
    if (stat.isDirectory()) return candidate;
    try {
      const pointer = readFileSync(join(candidate, '.git'), 'utf8').match(/^gitdir:\s*(.+?)\s*$/m)?.[1];
      const main = pointer ? resolve(candidate, pointer).match(/^(.+)\/\.git\/worktrees\/[^/]+$/)?.[1] : null;
      return main ?? candidate;
    } catch {
      return candidate;
    }
  }
  return null;
}

/** Every spelling Claude Code may have filed this directory's project entry under. */
function projectKeys(cwd) {
  const real = realOrSame(cwd);
  const root = gitProjectRoot(real);
  return [...new Set([cwd, real, ...(root ? [root, realOrSame(root)] : [])])];
}

/**
 * The remote servers Claude Code would connect in this directory, as
 * `{ url, name }`: user scope and local scope from `.claude.json`, project
 * scope from `.mcp.json` here or in any folder above, leaving out any the
 * person disabled.
 */
export function configuredServers({ env = process.env, cwd } = {}) {
  const doc = readJson(claudeConfigPath(env));
  const found = new Map();
  const take = (entries, skip = []) => {
    if (!entries || typeof entries !== 'object') return;
    for (const [name, entry] of Object.entries(entries)) {
      if (skip.includes(name)) continue;
      const server = readEntry(name, entry);
      if (server !== null && !found.has(server.url)) found.set(server.url, server);
    }
  };
  take(own(doc, 'mcpServers'));
  if (typeof cwd === 'string' && cwd !== '') {
    // A server disabled under any spelling of the project still counts when
    // reading the files.
    const disabled = [];
    for (const key of projectKeys(cwd)) {
      const project = own(own(doc, 'projects'), key);
      take(own(project, 'mcpServers'));
      const off = own(project, 'disabledMcpjsonServers');
      if (Array.isArray(off)) disabled.push(...off);
    }
    for (const dir of upFrom(realOrSame(cwd))) take(own(readJson(join(dir, '.mcp.json')), 'mcpServers'), disabled);
  }
  return [...found.values()].slice(0, MAX_CONFIGURED);
}

/**
 * Every server URL Claude Code knows about anywhere: all scopes, every project
 * it has opened, and this directory's `.mcp.json` files. A pin that is in none
 * of these was removed, or was never added because the person said no at the
 * ask. Credentials do not matter here and nothing from this leaves the machine:
 * it is only compared with URLs already pinned. Null when the config cannot be
 * read, so a broken file never reads as "everything was removed".
 */
export function knownServerUrls({ env = process.env, cwd } = {}) {
  const doc = readJson(claudeConfigPath(env));
  if (doc === null) return null;
  const urls = new Set();
  const take = (entries) => {
    if (!entries || typeof entries !== 'object') return;
    for (const entry of Object.values(entries)) {
      try {
        urls.add(new URL(entry.url).toString());
      } catch {
        /* no usable URL in this entry */
      }
    }
  };
  take(own(doc, 'mcpServers'));
  const dirs = typeof cwd === 'string' && cwd !== '' ? upFrom(realOrSame(cwd)) : [];
  const projects = own(doc, 'projects');
  if (projects && typeof projects === 'object') {
    for (const [dir, project] of Object.entries(projects).slice(0, MAX_PROJECTS)) {
      take(own(project, 'mcpServers'));
      dirs.push(dir);
    }
  }
  for (const dir of new Set(dirs)) take(own(readJson(join(dir, '.mcp.json')), 'mcpServers'));
  return urls;
}
