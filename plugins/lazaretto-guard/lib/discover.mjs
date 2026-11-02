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
import { join } from 'node:path';
import { shareableUrl } from './mcp-scan.mjs';
import { cleanServerName } from './pins.mjs';

/** Bigger than any real config. A file past this is left unread. */
const MAX_CONFIG_BYTES = 20_000_000;

/** Most servers taken from the config, so a hostile `.mcp.json` stays bounded. */
const MAX_CONFIGURED = 50;

/** Fields that mean an entry authenticates. Their presence means skip. */
const CREDENTIAL_FIELDS = ['headers', 'headersHelper', 'oauth', 'env'];

/** Host labels that only mean something inside a private network. */
const PRIVATE_LABELS = new Set(['local', 'localhost', 'internal', 'intranet', 'corp', 'lan', 'vpn', 'home', 'test', 'invalid']);

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

/** True for an IP literal, a single-label name, or a name with a private label anywhere in it. */
export function isPrivateHost(hostname) {
  const host = hostname.toLowerCase();
  if (!host.includes('.') || host.startsWith('[') || /^[\d.]+$/.test(host)) return true;
  return host.split('.').some((label) => PRIVATE_LABELS.has(label));
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

/**
 * The remote servers Claude Code would connect in this directory, as
 * `{ url, name }`: user scope and local scope from `.claude.json`, project
 * scope from `.mcp.json`, leaving out any the person disabled.
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
    const dirs = [cwd];
    try {
      const real = realpathSync(cwd);
      if (real !== cwd) dirs.push(real);
    } catch {
      /* a directory that cannot be resolved is read as given */
    }
    // Claude Code may have filed this project under either spelling of the path,
    // so a server disabled under one still counts when reading the file once.
    const disabled = [];
    for (const dir of dirs) {
      const project = own(own(doc, 'projects'), dir);
      take(own(project, 'mcpServers'));
      const off = own(project, 'disabledMcpjsonServers');
      if (Array.isArray(off)) disabled.push(...off);
    }
    take(own(readJson(join(cwd, '.mcp.json')), 'mcpServers'), disabled);
  }
  return [...found.values()].slice(0, MAX_CONFIGURED);
}
