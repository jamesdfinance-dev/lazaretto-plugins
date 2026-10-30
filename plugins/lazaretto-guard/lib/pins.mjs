/**
 * Tool pins: what a remote MCP server told an agent when it was added, kept so
 * a later read can say what changed.
 *
 * A server can pass the read at `claude mcp add` and change its tool
 * descriptions a week later (a "rug pull"). Claude Code approved it once and
 * never looks again, and the verdict we gave at the add was right when it was
 * made. So the add keeps the scan's fingerprint (one hash over every tool and
 * the instructions, plus one hash per tool), and a re-read at most once a day
 * compares against it. The per-tool hashes are what let us say which tool
 * changed.
 *
 * Only names and hashes are kept, never tool text. A name is the server's own
 * text, so one that is not a plain identifier is replaced by a hash of it
 * before it is stored or shown, the same way the API reports it.
 *
 * The file is `~/.config/lazaretto/pins.json`, next to the key, readable by
 * the owner only. Nothing here touches the network; decide.mjs does the reads.
 * Every function that reads the file treats a missing or broken file as "no
 * pins", because a pin file is never a reason for the hook to fail.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, renameSync, chmodSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { configDir } from './paths.mjs';

/** How long a pin goes without a re-read. */
export const RECHECK_MS = 24 * 60 * 60 * 1000;

/** Most servers kept, so the file and a session start stay bounded. */
const MAX_PINS = 50;

/** Most servers re-read in one session start. The rest wait for the next one. */
export const MAX_RECHECK = 5;

/** Most tool names shown in one list before "and N more". */
const MAX_NAMES = 10;

const HASH = /^[0-9a-f]{64}$/;
/** What the API reports a tool under: a plain name (with #2 for a repeat) or tool-<hash>. */
const PLAIN_NAME = /^[\w.\-/:]{1,64}(#\d{1,3})?$/;
/** A server name as typed on `claude mcp add`. Anything else is not kept. */
const SERVER_NAME = /^[\w.\-]{1,64}$/;

const hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

export function pinsPath(env = process.env) {
  return join(configDir(env), 'pins.json');
}

/**
 * The fingerprint from a scan report, checked and cleaned, or null when there
 * is none worth pinning. A partial read (a cap cut it short) is null: it is
 * not comparable with a complete one, and pinning it would report a change
 * the server never made.
 */
export function readFingerprint(raw) {
  if (!raw || typeof raw !== 'object' || raw.partial === true) return null;
  if (typeof raw.sha256 !== 'string' || !HASH.test(raw.sha256)) return null;
  if (!raw.tools || typeof raw.tools !== 'object') return null;
  const tools = Object.create(null);
  for (const [name, hash] of Object.entries(raw.tools)) {
    if (typeof hash !== 'string' || !HASH.test(hash)) return null;
    tools[PLAIN_NAME.test(name) ? name : `tool-${hex(name).slice(0, 12)}`] = hash;
  }
  const fp = { sha256: raw.sha256, tools };
  if (raw.instructions !== undefined) {
    if (typeof raw.instructions !== 'string' || !HASH.test(raw.instructions)) return null;
    fp.instructions = raw.instructions;
  }
  return fp;
}

/** A server name worth keeping, or null. */
export function cleanServerName(name) {
  return typeof name === 'string' && SERVER_NAME.test(name) ? name : null;
}

/** The pins on disk. A missing or unreadable file is no pins. */
export function loadPins(env = process.env) {
  const empty = { servers: Object.create(null) };
  let doc;
  try {
    doc = JSON.parse(readFileSync(pinsPath(env), 'utf8'));
  } catch {
    return empty;
  }
  if (!doc || typeof doc !== 'object' || !doc.servers || typeof doc.servers !== 'object') return empty;
  const servers = Object.create(null);
  for (const [url, entry] of Object.entries(doc.servers)) {
    const fp = readFingerprint(entry);
    if (fp === null) continue;
    const kept = {
      name: cleanServerName(entry.name),
      ...fp,
      pinned_at: typeof entry.pinned_at === 'string' ? entry.pinned_at : new Date(0).toISOString(),
      checked_at: typeof entry.checked_at === 'string' ? entry.checked_at : new Date(0).toISOString(),
    };
    const to = entry.change ? readFingerprint(entry.change.to) : null;
    if (to !== null) kept.change = { ...entry.change, to };
    servers[url] = kept;
  }
  return { servers };
}

/** True when there is a pin file at all. Cheap: the hook asks this on every MCP tool call. */
export function hasPins(env = process.env) {
  return existsSync(pinsPath(env));
}

/** Write the pins, owner-only, whole or not at all. */
export function savePins(pins, env = process.env) {
  const file = pinsPath(env);
  mkdirSync(configDir(env), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify({ version: 1, servers: pins.servers }, null, 2)}\n`, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  // A rename is atomic, so a hook killed mid-write leaves the old file, never half a new one.
  renameSync(tmp, file);
}

/** Pin what a server advertises now. A re-add replaces the old pin and any pending change. */
export function pinServer(pins, { url, name, fingerprint, now = new Date() }) {
  const at = now.toISOString();
  pins.servers[url] = { name: cleanServerName(name), ...fingerprint, pinned_at: at, checked_at: at };
  const urls = Object.keys(pins.servers);
  if (urls.length > MAX_PINS) {
    urls.sort((a, b) => pins.servers[a].pinned_at.localeCompare(pins.servers[b].pinned_at));
    for (const old of urls.slice(0, urls.length - MAX_PINS)) delete pins.servers[old];
  }
  return pins;
}

/** The pinned servers due a re-read, least recently read first. */
export function dueForRecheck(pins, now = new Date()) {
  return Object.keys(pins.servers)
    .filter((url) => now.getTime() - Date.parse(pins.servers[url].checked_at) >= RECHECK_MS || Number.isNaN(Date.parse(pins.servers[url].checked_at)))
    .sort((a, b) => pins.servers[a].checked_at.localeCompare(pins.servers[b].checked_at))
    .slice(0, MAX_RECHECK);
}

/** Which tools differ between two fingerprints, or null when nothing an agent reads changed. */
export function diffTools(before, after) {
  if (before.sha256 === after.sha256) return null;
  const has = (fp, n) => Object.prototype.hasOwnProperty.call(fp.tools, n);
  return {
    added: Object.keys(after.tools).filter((n) => !has(before, n)).sort(),
    removed: Object.keys(before.tools).filter((n) => !has(after, n)).sort(),
    edited: Object.keys(after.tools).filter((n) => has(before, n) && before.tools[n] !== after.tools[n]).sort(),
    instructions_changed: before.instructions !== after.instructions,
  };
}

/**
 * Record a re-read of one pinned server. `fingerprint` null means the read did
 * not complete (unreachable, no credits, a partial read): the pin is kept as it
 * is and the server waits a day like any other. Returns what happened:
 * 'unread', 'unchanged', 'changed' (a change not seen before) or 'known'.
 */
export function recordRecheck(entry, { fingerprint, scan = null, now = new Date() }) {
  entry.checked_at = now.toISOString();
  if (fingerprint === null) return 'unread';
  if (fingerprint.sha256 === entry.sha256) {
    // Changed back before anyone was told: nothing to tell.
    delete entry.change;
    return 'unchanged';
  }
  if (entry.change && entry.change.to.sha256 === fingerprint.sha256) return 'known';
  entry.change = { ...diffTools(entry, fingerprint), to: fingerprint, seen_at: now.toISOString() };
  if (scan && (scan.verdict === 'flagged' || scan.verdict === 'malicious')) {
    entry.change.verdict = scan.verdict;
    entry.change.risk = scan.risk;
    // Our rule text and where it fired. Never the snippet: that is the server's text.
    entry.change.findings = scan.findings.slice(0, 5).map((f) => ({
      rule_id: typeof f.rule_id === 'string' ? f.rule_id : 'finding',
      severity: typeof f.severity === 'string' ? f.severity : undefined,
      description: typeof f.description === 'string' ? f.description.slice(0, 160) : undefined,
      evidence: { file: f.evidence?.file, line: f.evidence?.line },
    }));
  }
  return 'changed';
}

/** The new tools become the pin. Called once the person has been told. */
export function acceptChange(entry, now = new Date()) {
  if (!entry.change) return;
  const { sha256, tools, instructions } = entry.change.to;
  entry.sha256 = sha256;
  entry.tools = tools;
  if (instructions === undefined) delete entry.instructions;
  else entry.instructions = instructions;
  entry.pinned_at = now.toISOString();
  delete entry.change;
}

/** How Claude Code names a server inside its tool names. */
function toolPrefix(name) {
  return `mcp__${name.replace(/[^A-Za-z0-9_-]/g, '_')}__`;
}

/** The pinned servers with a change the person has not been asked about, behind this tool call. */
export function pendingForTool(pins, toolName) {
  if (typeof toolName !== 'string' || !toolName.startsWith('mcp__')) return [];
  return Object.entries(pins.servers).filter(([, e]) => e.change && e.name && toolName.startsWith(toolPrefix(e.name)));
}

function nameList(label, names) {
  if (!Array.isArray(names) || names.length === 0) return null;
  const shown = names.slice(0, MAX_NAMES).join(', ');
  return `    ${label}: ${shown}${names.length > MAX_NAMES ? `, and ${names.length - MAX_NAMES} more` : ''}`;
}

/** The lines naming what changed on one server. Names and dates only, never tool text. */
export function describeChange(url, entry) {
  const c = entry.change;
  const lines = [`  ${entry.name ? `${entry.name}  ` : ''}${url}  pinned ${entry.pinned_at.slice(0, 10)}, changed by ${c.seen_at.slice(0, 10)}`];
  for (const line of [nameList('added', c.added), nameList('removed', c.removed), nameList('changed', c.edited)]) {
    if (line !== null) lines.push(line);
  }
  if (c.instructions_changed) lines.push("    the server's instructions changed");
  if (c.verdict) {
    lines.push(`    the new tools read ${c.verdict}${c.risk ? `, risk ${c.risk}` : ''}:`);
    for (const f of c.findings ?? []) {
      const where = [f.evidence?.file, f.evidence?.line ? `line ${f.evidence.line}` : null].filter(Boolean).join(', ');
      lines.push(`      ${f.rule_id}${f.severity ? ` [${f.severity}]` : ''}${where ? ` (${where})` : ''}${f.description ? `: ${f.description}` : ''}`);
    }
  }
  return lines.join('\n');
}
