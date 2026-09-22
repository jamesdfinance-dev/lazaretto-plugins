/**
 * The only thing in this plugin that touches the network.
 *
 * It sends package names and versions to POST /check and reads the answer.
 * Nothing else is sent: not the command, not the working directory, not a file
 * path, not a project name, not an API key. There is no key to send, because
 * this path is free and anonymous.
 *
 * Every failure is silence. A guard that speaks when it does not know is worse
 * than no guard, and a guard that stalls an install gets uninstalled.
 */

export const DEFAULT_ORIGIN = 'https://lazaretto.dev';
export const DEFAULT_PATH = '/check';

/**
 * Find the malicious hits in a `/check` answer.
 *
 * `/check` renders for a terminal, so the answer is text. We match the lines in
 * its KNOWN MALWARE block against the specs we asked about rather than trying
 * to re-parse the layout, because the column padding collapses for very long
 * package names and a layout parser would read those lines wrong.
 *
 * A JSON body (what /v1/lockfile returns, and what /check would return if it
 * ever honours `accept: application/json`) is read directly.
 */
export function readAnswer(body, specs) {
  if (typeof body !== 'string' || body === '') return [];
  const trimmed = body.trimStart();
  if (trimmed.startsWith('{')) {
    let doc = null;
    try {
      doc = JSON.parse(body);
    } catch {
      return [];
    }
    if (!doc || !Array.isArray(doc.malicious)) return [];
    return doc.malicious
      .filter((m) => m && typeof m.name === 'string' && typeof m.version === 'string')
      .map((m) => ({
        name: m.name,
        version: m.version,
        ids: Array.isArray(m.ids) ? m.ids.filter((id) => typeof id === 'string') : [],
      }));
  }
  return readTextAnswer(body, specs);
}

/**
 * Does this line name exactly `ref`, rather than a longer ref that begins the
 * same way?
 *
 * A plain prefix test is wrong: `chalk@5.6.1` prefixes the line for
 * `chalk@5.6.10`, so a clean package would be reported as an advisory hit, and
 * the leftover `0` would be read as part of an advisory id.
 *
 * Whitespace alone is not enough of a boundary either, because the route pads
 * to at most 46 columns and the ids run straight into a longer ref with no gap.
 * So a boundary is: end of line, whitespace, or the start of an advisory id,
 * which is an uppercase letter (GHSA, MAL, CVE, OSV). A version cannot continue
 * with a bare uppercase letter: semver puts a `-` or a `+` first, and both of
 * those read here as a different ref, which is silence rather than a wrong hit.
 */
function namesRef(line, ref) {
  if (!line.startsWith(ref)) return false;
  const next = line.charAt(ref.length);
  return next === '' || /\s/.test(next) || /[A-Z]/.test(next);
}

/** The text rendering of the same answer. */
export function readTextAnswer(text, specs) {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => /^\s*KNOWN MALWARE \(\d+\)\s*$/.test(l));
  if (start === -1) return [];
  const block = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    if (lines[i].trim() === '') break;
    block.push(lines[i].trim());
  }
  const hits = [];
  for (const spec of specs) {
    const ref = `${spec.name}@${spec.version}`;
    const line = block.find((l) => namesRef(l, ref));
    if (line === undefined) continue;
    const rest = line.slice(ref.length).trim();
    hits.push({
      name: spec.name,
      version: spec.version,
      ids: rest === '' ? [] : rest.split(/\s*,\s*/).filter((id) => id !== ''),
    });
  }
  return hits;
}

/**
 * Ask the API about a list of specs.
 *
 * Resolves to `{ hits }` on a clean answer, or `null` for every other outcome:
 * a non-200, an unreadable body, a network error, a timeout, a rate limit. The
 * caller treats null exactly like an empty hit list, which is silence.
 */
export async function checkSpecs(specs, options = {}) {
  const {
    origin = DEFAULT_ORIGIN,
    path = DEFAULT_PATH,
    timeoutMs = 1000,
    clientTag = 'lazaretto-guard',
    fetchImpl = globalThis.fetch,
  } = options;

  if (!Array.isArray(specs) || specs.length === 0) return null;
  if (typeof fetchImpl !== 'function') return null;

  const body = JSON.stringify({ packages: specs.map((s) => `${s.name}@${s.version}`) });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(`${origin}${path}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'text/plain, application/json',
        // A stable client string so hook traffic is separable from curl traffic
        // on the API side. Kept free of the word "bot" on purpose: the API
        // classifies user agents and a bot-looking one would be filtered out of
        // its own funnel.
        'user-agent': clientTag,
        'x-lazaretto-client': clientTag,
      },
      body,
      signal: controller.signal,
    });
    if (!res || res.status !== 200) return null;
    const text = await res.text();
    return { hits: readAnswer(text, specs) };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
