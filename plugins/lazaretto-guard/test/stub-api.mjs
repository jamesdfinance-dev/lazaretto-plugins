/**
 * A stand-in for POST /check.
 *
 * The clean and hit renderings copy the real route's text layout, including the
 * column padding, so a change in how we read the answer shows up here rather
 * than in someone's terminal. Kept in one place because three test files need
 * it and a hanging variant is the only way to prove the hook cannot stall.
 */
import { createServer } from 'node:http';

/** The real route's padding, copied so the layout under test is the real one. */
function pad(s, n) {
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

/** What POST /check prints when nothing matched. */
export function cleanText(count) {
  return [
    `Lazaretto checked ${count} pinned ${count === 1 ? 'dependency' : 'dependencies'} against published malicious-package advisories.`,
    '',
    '  Nothing matched a published advisory.',
    '  That means no known-bad match, not that the code is without risk:',
    '  a package can be hostile before anyone has reported it.',
    '',
  ].join('\n');
}

/** What POST /check prints when something matched. */
export function hitText(count, hits) {
  const lines = [];
  lines.push(`Lazaretto checked ${count} pinned ${count === 1 ? 'dependency' : 'dependencies'} against published malicious-package advisories.`);
  lines.push('');
  lines.push(`  KNOWN MALWARE (${hits.length})`);
  const width = Math.min(46, Math.max(...hits.map((h) => h.ref.length)) + 2);
  for (const h of hits) {
    lines.push(`    ${pad(h.ref, width)}${h.ids.join(', ')}`);
  }
  lines.push('');
  lines.push('  Remove or upgrade these before installing. Each id above is a published');
  lines.push('  advisory you can read yourself at https://osv.dev/vulnerability/<id>.');
  lines.push('');
  return lines.join('\n');
}

/**
 * Start a stub on an ephemeral port.
 *
 * `behaviour` is one of:
 *   'clean'  200 with nothing matched
 *   'hit'    200 with the `hits` list matched
 *   'error'  500
 *   'limit'  429
 *   'hang'   accepts the request and never answers
 *   'json'   200 with the /v1/lockfile JSON shape
 */
export async function startStub({ behaviour = 'clean', hits = [], delayMs = 0 } = {}) {
  const received = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      let parsed = null;
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = null;
      }
      received.push({ url: req.url, headers: req.headers, body: parsed, raw });
      const count = Array.isArray(parsed?.packages) ? parsed.packages.length : 0;

      const answer = () => {
        if (behaviour === 'hang') return;
        if (behaviour === 'error') {
          res.writeHead(500, { 'content-type': 'text/plain' });
          res.end('nope');
          return;
        }
        if (behaviour === 'limit') {
          res.writeHead(429, { 'content-type': 'text/plain' });
          res.end('slow down');
          return;
        }
        if (behaviour === 'json') {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(
            JSON.stringify({
              checked: count,
              malicious: hits.map((h) => {
                const at = h.ref.lastIndexOf('@');
                return { name: h.ref.slice(0, at), version: h.ref.slice(at + 1), ids: h.ids };
              }),
              unverified: [],
            }),
          );
          return;
        }
        res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
        res.end(behaviour === 'hit' ? hitText(count, hits) : cleanText(count));
      };

      if (delayMs > 0) setTimeout(answer, delayMs).unref();
      else answer();
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    origin: `http://127.0.0.1:${port}`,
    received,
    async close() {
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
