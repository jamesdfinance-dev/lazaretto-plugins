/**
 * Read a remote MCP server's tools before it is connected.
 *
 * The advisory check in api.mjs answers one question: is this exact package
 * version listed as malware? That is worth asking, but free tools ask it too,
 * and npm usually pulls a listed version within hours. What nobody else does
 * at install time is read the text an MCP server hands an agent (its tool
 * names, descriptions, parameter schemas and instructions) for hidden orders:
 * tool poisoning, parameters built to carry secrets out, standing orders about
 * another server's tools. That is what this module adds, for remote servers
 * added with `claude mcp add <name> <url>` or written into an MCP config.
 *
 * What leaves the machine on this path: the server's URL, so our scanner can
 * ask the server for its tool list itself, and a free API key. Nothing else.
 * A URL that carries a secret (a query string, user:password@, or an auth
 * header on the command) is never sent: a server that needs credentials to
 * list its tools is not one we can read anyway, and a secret has no business
 * leaving the machine for a check.
 *
 * Same contract as everything else in this plugin: the result is ask or
 * nothing. A failure of any kind, including no key, no credits, a slow answer
 * or an unreachable service, is silence.
 */
import { mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tokenize } from './tokenize.mjs';
import { configDir } from './paths.mjs';
import { readFingerprint } from './pins.mjs';

/** Most servers we will read in one command, so one hook stays bounded. */
const MAX_SERVERS = 3;

/** Flags on `claude mcp add` that carry credentials. Their presence means skip. */
const AUTH_FLAGS = new Set(['--header', '-H', '--client-secret', '--client-id']);

/**
 * A URL we are willing to send for a scan: http(s), no credentials in it, no
 * query string or fragment (where tokens usually live). Returns the URL to
 * send, or null.
 */
export function shareableUrl(raw) {
  if (typeof raw !== 'string' || !/^https?:\/\//i.test(raw)) return null;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.username !== '' || u.password !== '') return null;
  if (u.search !== '' || u.hash !== '') return null;
  return u.toString();
}

/** Options on `claude mcp add` that take a value, so the value is not read as the server name. */
const VALUE_FLAGS = new Set(['--transport', '-t', '--scope', '-s', '--env', '-e', '--callback-port']);

/**
 * The remote MCP servers a Bash command is about to add, as `{ url, name }`.
 * Only `claude mcp add` segments are read; a URL anywhere else in a command is
 * not a server being connected. A segment carrying an auth flag yields
 * nothing. The name is the positional just before the URL, or null when that
 * cannot be told apart from an option's value.
 */
export function remoteMcpServersFromCommand(command) {
  const { ok, segments } = tokenize(command);
  if (!ok) return [];
  const servers = [];
  for (const tokens of segments) {
    // `claude` has to be the command itself, after any VAR=value prefixes.
    // `echo claude mcp add ...` mentions a server; it does not connect one.
    let cmd = 0;
    while (cmd < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[cmd])) cmd += 1;
    if (!/(^|\/)claude$/.test(tokens[cmd] ?? '') || tokens[cmd + 1] !== 'mcp' || tokens[cmd + 2] !== 'add') continue;
    const rest = tokens.slice(cmd + 3);
    if (rest.some((t) => AUTH_FLAGS.has(t) || t.startsWith('--header=') || t.startsWith('--client-secret='))) continue;
    // Anything after `--` is a stdio command, handled by the advisory check.
    const sep = rest.indexOf('--');
    const head = sep === -1 ? rest : rest.slice(0, sep);
    head.forEach((t, i) => {
      const url = shareableUrl(t);
      if (url === null || servers.some((s) => s.url === url)) return;
      const prev = head[i - 1];
      const named = i > 0 && !prev.startsWith('-') && !(i > 1 && VALUE_FLAGS.has(head[i - 2]));
      servers.push({ url, name: named ? prev : null });
    });
  }
  return servers.slice(0, MAX_SERVERS);
}

/** The URLs alone, for callers that do not need the names. */
export function remoteMcpUrlsFromCommand(command) {
  return remoteMcpServersFromCommand(command).map((s) => s.url);
}

/**
 * Remote servers in MCP config text (a whole file or an edit fragment), as
 * `{ url, name }`. An entry with headers is skipped for the same reason as an
 * auth flag. A fragment carries no reliable name, so its name is null.
 */
export function remoteMcpServersFromConfigText(text) {
  if (typeof text !== 'string' || text === '') return [];
  const servers = [];
  const add = (url, name) => {
    if (url !== null && !servers.some((s) => s.url === url)) servers.push({ url, name });
  };
  let doc = null;
  try {
    doc = JSON.parse(text);
  } catch {
    doc = null;
  }
  if (doc && typeof doc === 'object') {
    const entries = doc.mcpServers && typeof doc.mcpServers === 'object' ? doc.mcpServers : doc;
    for (const [name, entry] of Object.entries(entries)) {
      if (!entry || typeof entry !== 'object' || entry.headers) continue;
      add(shareableUrl(entry.url), name);
    }
    return servers.slice(0, MAX_SERVERS);
  }
  // An edit fragment: take "url": "..." pairs, unless the fragment mentions headers.
  if (/"headers"\s*:/.test(text)) return [];
  for (const m of text.matchAll(/"url"\s*:\s*"([^"]{1,2048})"/g)) add(shareableUrl(m[1]), null);
  return servers.slice(0, MAX_SERVERS);
}

/** The URLs alone, for callers that do not need the names. */
export function remoteMcpUrlsFromConfigText(text) {
  return remoteMcpServersFromConfigText(text).map((s) => s.url);
}

/** Where the free key is kept between runs. */
export function keyPath(env = process.env) {
  return join(configDir(env), 'key');
}

/**
 * An API key for the scan: LAZARETTO_API_KEY if set, else the one this plugin
 * saved before, else (unless `mint` is false) a free one minted now and saved
 * (readable by the owner only). Resolves to null when none can be had; the
 * caller stays silent.
 */
export async function obtainKey({ env = process.env, origin, timeoutMs, clientTag, mint = true, fetchImpl = fetch } = {}) {
  const fromEnv = env.LAZARETTO_API_KEY?.trim();
  if (fromEnv) return fromEnv;
  const file = keyPath(env);
  try {
    const saved = readFileSync(file, 'utf8').trim();
    if (saved !== '') return saved;
  } catch {
    /* no saved key yet */
  }
  if (!mint) return null;
  try {
    const res = await fetchImpl(`${origin}/v1/trial`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-lazaretto-client': clientTag ?? 'lazaretto-guard', 'user-agent': clientTag ?? 'lazaretto-guard' },
      body: '{}',
      signal: AbortSignal.timeout(Math.max(100, timeoutMs ?? 1500)),
    });
    if (!res.ok) return null;
    const body = await res.json();
    const key = typeof body?.api_key === 'string' ? body.api_key.trim() : '';
    if (key === '') return null;
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    writeFileSync(file, `${key}\n`, { mode: 0o600 });
    chmodSync(file, 0o600);
    return key;
  } catch {
    return null;
  }
}

/**
 * Scan one remote MCP server. Resolves to `{ url, verdict, risk, findings,
 * fingerprint }` for a completed scan, or null for anything else (no credits,
 * an error verdict, a timeout). Null is silence, never a clear. `fingerprint`
 * is null when the report has none worth pinning (an older API, a partial read).
 */
export async function scanRemoteServer(url, { origin, key, timeoutMs, clientTag, fetchImpl = fetch }) {
  try {
    const res = await fetchImpl(`${origin}/v1/scan`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': key,
        'x-lazaretto-client': clientTag ?? 'lazaretto-guard',
        'user-agent': clientTag ?? 'lazaretto-guard',
      },
      body: JSON.stringify({ target: { type: 'mcp_server', ref: url }, depth: 'full' }),
      signal: AbortSignal.timeout(Math.max(100, timeoutMs)),
    });
    if (!res.ok) return null;
    const report = await res.json();
    if (!report || typeof report.verdict !== 'string' || report.verdict === 'error') return null;
    return {
      url,
      verdict: report.verdict,
      risk: typeof report.risk === 'string' ? report.risk : null,
      findings: Array.isArray(report.findings) ? report.findings : [],
      fingerprint: readFingerprint(report.tool_fingerprint),
    };
  } catch {
    return null;
  }
}

/** True when a scan result is worth interrupting someone for. */
export function isConcerning(result) {
  return result !== null && (result.verdict === 'flagged' || result.verdict === 'malicious');
}

/** The lines shown to the person for one concerning server. */
export function describeServer(result) {
  const lines = [`  ${result.url}  verdict ${result.verdict}${result.risk ? `, risk ${result.risk}` : ''}`];
  // A finding is { rule_id, severity, description, evidence: { file, line,
  // snippet } }. The snippet is deliberately NOT shown: it is a quote of the
  // very text being flagged, and putting a server's injection attempt into a
  // permission prompt is the last thing a guard should do. The description is
  // our own rule text.
  for (const f of result.findings.slice(0, 5)) {
    const ev = f.evidence ?? {};
    const where = [ev.file, ev.line ? `line ${ev.line}` : null].filter(Boolean).join(', ');
    const what = typeof f.description === 'string' ? f.description.slice(0, 160) : '';
    lines.push(`    ${f.rule_id ?? 'finding'}${f.severity ? ` [${f.severity}]` : ''}${where ? ` (${where})` : ''}${what ? `: ${what}` : ''}`);
  }
  if (result.findings.length > 5) lines.push(`    and ${result.findings.length - 5} more`);
  return lines.join('\n');
}
