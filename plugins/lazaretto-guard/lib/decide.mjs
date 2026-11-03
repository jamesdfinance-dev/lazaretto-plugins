/**
 * The decision.
 *
 * There are exactly two outcomes: ask, or nothing. There is no deny, and there
 * never will be. One wrong block inside an agent run is a permanent uninstall,
 * and this plugin has no business being the thing that stops a build. When it
 * has evidence it hands the evidence to the person and lets them decide.
 *
 * There is also no upsell here. The free path never mentions paying. Blocking
 * and then selling reads as pay-to-unblock, and it would deserve to.
 */
import { parseCommand, parseMcpConfigText } from './parse.mjs';
import { checkSpecs, DEFAULT_ORIGIN, DEFAULT_PATH } from './api.mjs';
import {
  remoteMcpServersFromCommand,
  remoteMcpServersFromConfigText,
  obtainKey,
  scanRemoteServer,
  isConcerning,
  describeServer,
} from './mcp-scan.mjs';
import { configuredServers, knownServerUrls } from './discover.mjs';
import { fileURLToPath } from 'node:url';
import {
  hasPins,
  loadPins,
  savePins,
  pinServer,
  pinFirstRead,
  unseenServers,
  dueForFirstRead,
  markTried,
  markUnreadable,
  dueForRecheck,
  MAX_RECHECK,
  RECHECK_MS,
  recordRecheck,
  acceptChange,
  pendingForTool,
  describeChange,
} from './pins.mjs';

// The plugin's own command line tool. `bin/` is not used: claude.ai and Cowork refuse a
// plugin that has one, so this is not on PATH and messages give the full path.
const CLI_PATH = fileURLToPath(new URL('../cli/lazaretto-guard.mjs', import.meta.url));

/** Where a person goes to read the advisory behind an id, for themselves. */
const ADVISORY_URL = 'https://osv.dev/vulnerability/';

/** Read the runtime settings once, so tests can pass their own. */
export function settingsFromEnv(env = process.env) {
  const mode = (env.LAZARETTO_GUARD_MODE ?? 'full').toLowerCase();
  return {
    mode,
    disabled: env.LAZARETTO_GUARD_DISABLE === '1' || mode === 'off',
    // `offline` and `hash` both mean the hook sends nothing. See the README.
    offline: mode === 'offline' || mode === 'hash',
    origin: env.LAZARETTO_GUARD_API ?? DEFAULT_ORIGIN,
    path: env.LAZARETTO_GUARD_API_PATH ?? DEFAULT_PATH,
    // Both are measured from the moment this process started, and both sit
    // inside the 2 second timeout hooks.json declares. See the README for why
    // the window is this tight and what it costs.
    timeoutMs: positiveInt(env.LAZARETTO_GUARD_TIMEOUT_MS, 1450),
    budgetMs: positiveInt(env.LAZARETTO_GUARD_BUDGET_MS, 1600),
    // Reading a remote MCP server's tools takes longer than an identity lookup:
    // our scanner connects to the server and asks it to list them. People add a
    // server rarely and on purpose, so only that path gets the longer window,
    // and it still sits inside the timeout hooks.json declares.
    mcpTimeoutMs: positiveInt(env.LAZARETTO_GUARD_MCP_TIMEOUT_MS, 5500),
    mcpBudgetMs: positiveInt(env.LAZARETTO_GUARD_MCP_BUDGET_MS, 7000),
    // Re-reading pinned servers at session start, at most once a day. Claude's
    // first reply waits for SessionStart hooks, so this window is shorter than
    // the one for an add, and a server that misses it waits for the next day.
    sessionTimeoutMs: positiveInt(env.LAZARETTO_GUARD_SESSION_TIMEOUT_MS, 4000),
    sessionBudgetMs: positiveInt(env.LAZARETTO_GUARD_SESSION_BUDGET_MS, 5000),
    // `advisories` turns the MCP read off and keeps only the identity check,
    // for anyone who does not want a server URL to leave the machine.
    readServers: mode !== 'advisories',
    // Off leaves only the servers added through Claude, so the config is not read.
    discover: (env.LAZARETTO_GUARD_DISCOVER ?? '').toLowerCase() !== 'off',
    env,
  };
}

function positiveInt(raw, fallback) {
  const n = Number.parseInt(raw ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/**
 * Pull the pinned package identities out of one hook input.
 *
 * Returns `{ ok, targets }`. `ok: false` means the input was not readable and
 * the hook must stay silent.
 */
export function targetsForToolInput(toolName, toolInput) {
  if (!toolInput || typeof toolInput !== 'object') return { ok: false, targets: [] };

  if (toolName === 'Bash') {
    const command = toolInput.command;
    if (typeof command !== 'string') return { ok: false, targets: [] };
    return parseCommand(command);
  }

  if (toolName === 'Write' || toolName === 'Edit' || toolName === 'MultiEdit' || toolName === 'NotebookEdit') {
    const filePath = typeof toolInput.file_path === 'string' ? toolInput.file_path : '';
    if (!isMcpConfigPath(filePath)) return { ok: true, targets: [] };
    const added = addedText(toolInput);
    if (added === '') return { ok: true, targets: [] };
    return parseMcpConfigText(added);
  }

  return { ok: true, targets: [] };
}

/**
 * The remote MCP servers this tool call is about to connect, as `{ url, name }`:
 * `claude mcp add` with a URL, or a URL written into an MCP config file.
 */
export function serversForToolInput(toolName, toolInput) {
  if (!toolInput || typeof toolInput !== 'object') return [];
  if (toolName === 'Bash') {
    return typeof toolInput.command === 'string' ? remoteMcpServersFromCommand(toolInput.command) : [];
  }
  if (toolName === 'Write' || toolName === 'Edit' || toolName === 'MultiEdit') {
    const filePath = typeof toolInput.file_path === 'string' ? toolInput.file_path : '';
    if (!isMcpConfigPath(filePath)) return [];
    return remoteMcpServersFromConfigText(addedText(toolInput));
  }
  return [];
}

/** The URLs alone. */
export function remoteServersForToolInput(toolName, toolInput) {
  return serversForToolInput(toolName, toolInput).map((s) => s.url);
}

/** True when this input needs the longer window: it connects a remote server. */
export function needsLongBudget(hookInput, settings) {
  if (settings && (settings.disabled || settings.offline || !settings.readServers)) return false;
  return remoteServersForToolInput(hookInput?.tool_name, hookInput?.tool_input).length > 0;
}

/** True when this input is a session start that may read servers. With nothing due it is over at once. */
export function isSessionRead(hookInput, settings) {
  if (hookInput?.hook_event_name !== 'SessionStart') return false;
  return !(settings && (settings.disabled || settings.offline || !settings.readServers));
}

/** The ask shown at the first use of a server that changed, or that read flagged the first time it was read. */
export function buildChangeReason(pending) {
  const changed = pending.filter(([, e]) => !e.change.first_read);
  const first = pending.filter(([, e]) => e.change.first_read);
  const parts = [];
  if (changed.length > 0) parts.push(buildToolChangeReason(changed));
  if (first.length > 0) {
    parts.push(
      [
        firstReadHeading(first),
        '',
        ...first.map(([url, entry]) => describeChange(url, entry)),
        '',
        'These are signals from reading the text the server hands an agent, not a verdict on whoever runs it. Only our rule names are shown, never the text. ' +
          'To read the tools yourself, run /mcp, or paste the URL at https://lazaretto.dev/check/mcp. ' +
          'Lazaretto will not ask about this again unless the tools change.',
      ].join('\n'),
    );
  }
  return parts.join('\n\n');
}

function firstReadHeading(first) {
  return first.length === 1
    ? 'Lazaretto read the tools of an MCP server already in your config and found something worth a look:'
    : `Lazaretto read the tools of ${first.length} MCP servers already in your config and found something worth a look:`;
}

function buildToolChangeReason(changed) {
  const lines = [];
  lines.push(
    changed.length === 1
      ? 'Lazaretto: the tools this MCP server advertises changed since it was added.'
      : `Lazaretto: the tools of ${changed.length} MCP servers changed since they were added.`,
  );
  lines.push('');
  for (const [url, entry] of changed) lines.push(describeChange(url, entry));
  lines.push('');
  lines.push(
    'A server can change what its tools tell an agent after it was approved. Only tool names are shown here, never the new text. ' +
      'To read the tools yourself, run /mcp, or paste the URL at https://lazaretto.dev/check/mcp. ' +
      'The new tools are now the pinned version, so Lazaretto will not ask about this change again.',
  );
  return lines.join('\n');
}

/** The text shown when a server's own tool text looks wrong. */
export function buildServerReason(results) {
  const lines = [];
  lines.push(
    results.length === 1
      ? 'Lazaretto read the tools this MCP server advertises, before it is connected, and found something worth a look:'
      : `Lazaretto read the tools ${results.length} MCP servers advertise, before they are connected, and found something worth a look:`,
  );
  lines.push('');
  for (const r of results) lines.push(describeServer(r));
  lines.push('');
  lines.push(
    'These are signals from reading the text the server hands an agent, not a verdict on whoever runs it. A server that reads clean can still change its tools later.',
  );
  return lines.join('\n');
}

/** The files that add an MCP server by being written rather than by a command. */
export function isMcpConfigPath(filePath) {
  if (typeof filePath !== 'string' || filePath === '') return false;
  const lower = filePath.toLowerCase();
  const base = lower.slice(lower.lastIndexOf('/') + 1);
  if (base === '.mcp.json' || base === 'mcp.json' || base === 'claude_desktop_config.json') return true;
  return /\.claude\/settings(\.local)?\.json$/.test(lower) || /\.cursor\/mcp\.json$/.test(lower);
}

/** Whatever text this edit is adding to the file. */
function addedText(toolInput) {
  const parts = [];
  if (typeof toolInput.content === 'string') parts.push(toolInput.content);
  if (typeof toolInput.new_string === 'string') parts.push(toolInput.new_string);
  if (Array.isArray(toolInput.edits)) {
    for (const e of toolInput.edits) {
      if (e && typeof e.new_string === 'string') parts.push(e.new_string);
    }
  }
  return parts.join('\n');
}

/**
 * The text the person reads when we ask. Evidence first, then what the evidence
 * is and is not. No product name dropped twice, no pitch, no adjectives about
 * risk we cannot support.
 */
export function buildReason(hits, targets) {
  const n = hits.length;
  const total = targets.length;
  const lines = [];
  lines.push(
    `Lazaretto: ${n} of ${total} pinned ${total === 1 ? 'package' : 'packages'} in this command ` +
      `${n === 1 ? 'matches' : 'match'} a published malicious-package advisory.`,
  );
  lines.push('');
  for (const hit of hits) {
    const target = targets.find((t) => t.name === hit.name && t.version === hit.version);
    const via = target ? ` (via ${target.via})` : '';
    const ids = hit.ids.length > 0 ? `  ${hit.ids.join(', ')}` : '  no advisory id returned';
    lines.push(`  ${hit.name}@${hit.version}${via}${ids}`);
  }
  lines.push('');
  if (hits.some((h) => h.ids.length > 0)) {
    lines.push(`Read each advisory yourself at ${ADVISORY_URL}<id>.`);
  }
  lines.push(
    'This is identity matching against published advisories. It says nothing about the packages that did not match: a package can be hostile before anyone has reported it.',
  );
  return lines.join('\n');
}

/** The PreToolUse payload for an ask. Never deny. */
export function askPayload(reason) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'ask',
      permissionDecisionReason: reason,
    },
  };
}

/**
 * The whole decision, given a hook input.
 *
 * Resolves to the payload object to print, or null to print nothing. It never
 * throws: every path that could fail resolves to null.
 */
export async function decide(hookInput, options = {}) {
  try {
    const settings = options.settings ?? settingsFromEnv(options.env ?? process.env);
    if (settings.disabled) return null;

    if (hookInput?.hook_event_name === 'SessionStart') return await atSessionStart(hookInput, settings, options);

    const toolName = hookInput?.tool_name;
    if (typeof toolName === 'string' && toolName.startsWith('mcp__')) return askAboutChanges(toolName, settings);

    const { ok, targets } = targetsForToolInput(toolName, hookInput?.tool_input);
    const servers = settings.readServers ? serversForToolInput(toolName, hookInput?.tool_input) : [];
    if ((!ok || targets.length === 0) && servers.length === 0) return null;
    if (settings.offline) return null;

    const fetchImpl = options.fetchImpl ?? fetch;
    const advisory =
      ok && targets.length > 0
        ? checkSpecs(targets, {
            origin: settings.origin,
            path: settings.path,
            timeoutMs: settings.timeoutMs,
            clientTag: options.clientTag,
            fetchImpl: options.fetchImpl,
          })
        : Promise.resolve(null);

    const serverRead = servers.length > 0 ? readServers(servers, settings, options, fetchImpl) : Promise.resolve([]);

    const [answer, concerning] = await Promise.all([advisory.catch(() => null), serverRead.catch(() => [])]);
    const parts = [];
    if (answer !== null && answer.hits.length > 0) parts.push(buildReason(answer.hits, targets));
    if (concerning.length > 0) parts.push(buildServerReason(concerning));
    if (parts.length === 0) return null;
    return askPayload(parts.join('\n\n'));
  } catch {
    return null;
  }
}

/**
 * A call to an MCP tool. Local only, nothing is sent: ask when the server
 * behind it changed its tools since it was pinned, then make the new tools the
 * pin, so one change is asked about once.
 */
function askAboutChanges(toolName, settings) {
  const env = settings.env ?? process.env;
  if (!hasPins(env)) return null;
  const pins = loadPins(env);
  const changed = pendingForTool(pins, toolName);
  if (changed.length === 0) return null;
  const reason = buildChangeReason(changed);
  for (const [, entry] of changed) acceptChange(entry);
  try {
    savePins(pins, env);
  } catch {
    // Unsaved, it asks again next time. Better than not asking.
  }
  return askPayload(reason);
}

/**
 * Session start. Three jobs, in this order: tell the person once before any
 * server from their config is read; read the configured servers not pinned yet;
 * re-read the pinned servers not read in the last day. A session start cannot
 * ask, so what it finds is a message; the ask comes at the first call to one of
 * that server's tools. A server with no name to match a tool call by is told
 * about here and its new tools pinned at once.
 */
async function atSessionStart(hookInput, settings, options) {
  if (settings.offline || !settings.readServers) return null;
  const env = settings.env ?? process.env;
  const pins = loadPins(env);
  const unseen = settings.discover ? unseenServers(pins, configuredServers({ env, cwd: hookInput.cwd })) : [];
  const started = Date.now();
  const nowDate = new Date();
  const now = nowDate.toISOString();
  const messages = [];

  // The add path sends a URL because someone just asked to connect it. These
  // were configured with no thought of us, so nothing goes until the person has
  // been told and had a session to say no.
  let firstRead = [];
  if (unseen.length > 0 && pins.discovery.notice_at === null) {
    pins.discovery.notice_at = now;
    messages.push(buildDiscoveryNotice(unseen));
  } else {
    firstRead = dueForFirstRead(pins, unseen, nowDate);
  }
  const known = settings.discover && Object.keys(pins.servers).length > 0 ? knownServerUrls({ env, cwd: hookInput.cwd }) : null;
  const due = dueForRecheck(pins, nowDate, known).slice(0, MAX_RECHECK - firstRead.length);

  const finish = () => (messages.length === 0 ? null : { systemMessage: messages.join('\n\n') });
  try {
    if (messages.length > 0) savePins(pins, env);
  } catch {
    // Unsaved, this notice would repeat every session and the reads would never start.
    return null;
  }
  if (firstRead.length === 0 && due.length === 0) return finish();

  const fetchImpl = options.fetchImpl ?? fetch;
  let key = await obtainKey({ env, origin: settings.origin, mint: false });
  if (key === null && firstRead.length > 0) {
    // First use, for someone who only ever added servers from a terminal. A
    // refused key is not asked for again the same day.
    const tried = pins.discovery.mint_tried_at;
    if (tried === null || nowDate.getTime() - Date.parse(tried) >= RECHECK_MS) {
      pins.discovery.mint_tried_at = now;
      try {
        savePins(pins, env);
      } catch {
        return finish();
      }
      key = await obtainKey({ env, origin: settings.origin, timeoutMs: Math.min(1500, settings.sessionTimeoutMs), clientTag: options.clientTag, fetchImpl });
    }
  }
  if (key === null) return finish();

  // Mark the attempt first: if the window closes mid-read, a slow server still
  // waits a day instead of holding up every session start until then.
  for (const url of due) pins.servers[url].checked_at = now;
  for (const { url } of firstRead) markTried(pins, url, nowDate);
  try {
    savePins(pins, env);
  } catch {
    return finish();
  }
  const left = settings.sessionTimeoutMs - (Date.now() - started);
  if (left < 200) return finish();
  const read = (url, kind) =>
    scanRemoteServer(url, {
      origin: settings.origin,
      key,
      timeoutMs: left,
      clientTag: options.clientTag,
      read: kind,
      onUnreadable: kind === 'discover' ? () => markUnreadable(pins, url) : undefined,
      fetchImpl,
    });
  const [firstScans, recheckScans] = await Promise.all([
    Promise.all(firstRead.map(({ url }) => read(url, 'discover'))),
    Promise.all(due.map((url) => read(url, 'recheck'))),
  ]);

  const flagged = [];
  const flaggedUnpinned = [];
  firstRead.forEach(({ url, name }, i) => {
    const scan = firstScans[i];
    if (scan?.fingerprint) {
      if (pinFirstRead(pins, { url, name, scan, now: nowDate })) flagged.push([url, pins.servers[url]]);
    } else if (scan && isConcerning(scan)) {
      flaggedUnpinned.push(scan);
    }
  });
  const fresh = [];
  due.forEach((url, i) => {
    const entry = pins.servers[url];
    const outcome = recordRecheck(entry, { fingerprint: recheckScans[i]?.fingerprint ?? null, scan: recheckScans[i] });
    if (outcome === 'changed') fresh.push([url, entry]);
  });
  if (flagged.length > 0 || flaggedUnpinned.length > 0) messages.push(buildFirstReadMessage(flagged, flaggedUnpinned));
  if (fresh.length > 0) messages.push(buildChangeMessage(fresh));
  for (const [, entry] of [...flagged, ...fresh]) if (!entry.name) acceptChange(entry);
  try {
    savePins(pins, env);
  } catch {
    return null;
  }
  return finish();
}

/** Said once, in a session that sends nothing, before any server from the config is read. */
export function buildDiscoveryNotice(unseen) {
  const lines = [];
  lines.push(
    'Lazaretto: from your next session, this plugin also reads the remote MCP servers already in your Claude Code config, not only ones added through Claude, so it can tell you when their tools change. Nothing has been sent yet.',
  );
  lines.push('');
  for (const { url, name } of unseen.slice(0, 10)) lines.push(`  ${name ? `${name}  ` : ''}${url}`);
  if (unseen.length > 10) lines.push(`  and ${unseen.length - 10} more`);
  lines.push('');
  lines.push(
    'Each URL goes to lazaretto.dev, whose scanner connects to the server and lists its tools; a free key is requested if you do not have one. Servers with auth headers or OAuth settings, private hostnames, or a token in the URL are skipped. ' +
      'To turn this off, set LAZARETTO_GUARD_DISCOVER=off in the env section of your Claude Code settings. For one server, run: ' + `node "${CLI_PATH}" unpin <url>`,
  );
  return lines.join('\n');
}

/** What a session start says about configured servers that read flagged the first time. */
export function buildFirstReadMessage(flagged, unpinned = []) {
  const lines = [firstReadHeading([...flagged, ...unpinned]), ''];
  for (const [url, entry] of flagged) lines.push(describeChange(url, entry));
  for (const scan of unpinned) lines.push(describeServer(scan));
  lines.push('');
  lines.push(
    flagged.length > 0 && flagged.every(([, e]) => e.name)
      ? 'Claude Code will ask before the first call to one of its tools. Only our rule names are shown, never the text.'
      : 'Only our rule names are shown, never the text. To read the tools yourself, run /mcp, or paste the URL at https://lazaretto.dev/check/mcp.',
  );
  return lines.join('\n');
}

/** What a session start says about servers whose tools changed. */
export function buildChangeMessage(changed) {
  const lines = [];
  lines.push(
    changed.length === 1
      ? 'Lazaretto: an MCP server you added changed its tools since it was pinned.'
      : `Lazaretto: ${changed.length} MCP servers you added changed their tools since they were pinned.`,
  );
  lines.push('');
  for (const [url, entry] of changed) lines.push(describeChange(url, entry));
  lines.push('');
  lines.push(
    changed.every(([, e]) => e.name)
      ? 'Claude Code will ask before the first call to one of its tools. Only tool names are shown, never the new text.'
      : 'Only tool names are shown, never the new text. To read the tools yourself, run /mcp, or paste the URL at https://lazaretto.dev/check/mcp.',
  );
  return lines.join('\n');
}

/**
 * Get a key and read each server, all inside the MCP window. Each complete
 * read is pinned, so a later session can say what changed. Concerning results
 * only are returned.
 */
async function readServers(servers, settings, options, fetchImpl) {
  const started = Date.now();
  const key = await obtainKey({
    env: settings.env ?? process.env,
    origin: settings.origin,
    timeoutMs: Math.min(1500, settings.mcpTimeoutMs),
    clientTag: options.clientTag,
    fetchImpl,
  });
  if (key === null) return [];
  const left = settings.mcpTimeoutMs - (Date.now() - started);
  if (left < 200) return [];
  const results = await Promise.all(
    servers.map(({ url }) =>
      scanRemoteServer(url, { origin: settings.origin, key, timeoutMs: left, clientTag: options.clientTag, fetchImpl }),
    ),
  );
  pinAll(servers, results, settings.env ?? process.env);
  return results.filter(isConcerning);
}

/**
 * Pin every server read in full. Pinned whatever the verdict: a person who
 * goes ahead after an ask has still approved those tools, and a change from
 * them is still worth knowing.
 */
function pinAll(servers, results, env) {
  const read = results.map((r, i) => [servers[i], r]).filter(([, r]) => r !== null && r.fingerprint);
  if (read.length === 0) return;
  try {
    const pins = loadPins(env);
    for (const [server, r] of read) pinServer(pins, { url: server.url, name: server.name, fingerprint: r.fingerprint });
    savePins(pins, env);
  } catch {
    // A pin that could not be saved costs a later warning, never this answer.
  }
}
