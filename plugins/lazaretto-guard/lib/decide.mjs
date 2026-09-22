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

    const toolName = hookInput?.tool_name;
    const { ok, targets } = targetsForToolInput(toolName, hookInput?.tool_input);
    if (!ok || targets.length === 0) return null;
    if (settings.offline) return null;

    const answer = await checkSpecs(targets, {
      origin: settings.origin,
      path: settings.path,
      timeoutMs: settings.timeoutMs,
      clientTag: options.clientTag,
      fetchImpl: options.fetchImpl,
    });
    if (answer === null || answer.hits.length === 0) return null;

    return askPayload(buildReason(answer.hits, targets));
  } catch {
    return null;
  }
}
