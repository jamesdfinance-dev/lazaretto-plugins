/**
 * The MCP servers already in Claude Code's config, however they got there.
 *
 * The hook only sees what the agent does. A server added with `claude mcp add`
 * in the person's own terminal, one that was there before this plugin, and one
 * that came with a repository's `.mcp.json` never pass through a tool call, so
 * nothing else in this plugin would ever read them. Session start reads the
 * config and picks them up.
 *
 * Only what a check needs comes out of these files: a server's URL and name, and
 * the package a local server runs. An entry with auth settings is skipped whole,
 * and so is a URL that names a private host, because being listed in a config
 * is not the person handing it to us. Nothing here touches the network.
 */
import { readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { collectFromMcpConfigEntry } from './parse.mjs';
import { shareableUrl } from './mcp-scan.mjs';
import { cleanServerName } from './pins.mjs';

/** Claude Code's own file holds much more than servers and can get large. */
const MAX_USER_CONFIG_BYTES = 64 * 1024 * 1024;
/** A `.mcp.json` can come from anywhere, so it gets a small allowance. */
const MAX_PROJECT_CONFIG_BYTES = 1024 * 1024;
/** How far up from the working directory to look for a `.mcp.json`. */
const MAX_LEVELS = 8;
const MAX_REMOTE = 20;
const MAX_PACKAGES = 20;
const MAX_URL_LENGTH = 512;

/** Host labels that mean a private network, wherever they sit in the name. */
const PRIVATE_LABELS = new Set(['localhost', 'local', 'internal', 'intranet', 'corp', 'lan', 'home', 'private', 'vpn', 'test']);

function readJson(path, maxBytes) {
  try {
    if (statSync(path).size > maxBytes) return null;
    const doc = JSON.parse(readFileSync(path, 'utf8'));
    return doc && typeof doc === 'object' ? doc : null;
  } catch {
    return null;
  }
}

/**
 * True when a host looks published on the public internet. A bare IP or a
 * single-label name is not a name anyone published, and a private-sounding label
 * is left alone even if it happens to resolve. Erring here only costs a read.
 */
export function isPublicHost(hostname) {
  if (typeof hostname !== 'string' || hostname === '') return false;
  if (hostname.startsWith('[') || /^[\d.]+$/.test(hostname)) return false;
  const labels = hostname.toLowerCase().split('.').filter(Boolean);
  return labels.length >= 2 && !labels.some((l) => PRIVATE_LABELS.has(l));
}

/** The URL to read for one config entry, or null when this entry should not be read. */
function readableUrl(entry) {
  if (entry.headers || entry.headersHelper || entry.oauth) return null;
  if (typeof entry.url !== 'string' || entry.url.length > MAX_URL_LENGTH || entry.url.includes('${')) return null;
  const url = shareableUrl(entry.url);
  return url !== null && isPublicHost(new URL(url).hostname) ? url : null;
}

function serversIn(block) {
  return block && typeof block === 'object' ? Object.entries(block).filter(([, e]) => e && typeof e === 'object') : [];
}

/**
 * Every `[name, entry]` Claude Code would load for this directory: user scope
 * and local scope from its own file, project scope from `.mcp.json` here or in
 * a parent. Env wins over the home directory the way Claude Code's does.
 */
function configEntries(cwd, env) {
  const home = env.HOME || homedir();
  const user = readJson(join(env.CLAUDE_CONFIG_DIR || home, '.claude.json'), MAX_USER_CONFIG_BYTES);
  const entries = serversIn(user?.mcpServers);
  if (typeof cwd !== 'string' || cwd === '') return entries;
  const projects = user?.projects;
  if (projects && typeof projects === 'object' && Object.hasOwn(projects, cwd)) entries.push(...serversIn(projects[cwd]?.mcpServers));
  let dir = cwd;
  for (let i = 0; i < MAX_LEVELS; i += 1) {
    entries.push(...serversIn(readJson(join(dir, '.mcp.json'), MAX_PROJECT_CONFIG_BYTES)?.mcpServers));
    const up = dirname(dir);
    if (up === dir || dir === home) break;
    dir = up;
  }
  return entries;
}

/**
 * What the config holds that can be checked: `remote` as `{ url, name }` and
 * `packages` as the pinned package identities local servers run. A broken or
 * missing file is simply nothing found.
 */
export function configuredServers({ cwd, env = process.env }) {
  const remote = [];
  const packages = [];
  for (const [rawName, entry] of configEntries(cwd, env)) {
    const name = cleanServerName(rawName);
    if (typeof entry.url === 'string') {
      const url = readableUrl(entry);
      if (url !== null && !remote.some((s) => s.url === url)) remote.push({ url, name });
    } else {
      collectFromMcpConfigEntry(entry, packages, 1, name ? `MCP server ${name}` : 'MCP server config');
    }
  }
  return { remote: remote.slice(0, MAX_REMOTE), packages: packages.slice(0, MAX_PACKAGES) };
}
