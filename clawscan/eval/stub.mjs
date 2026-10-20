import { createServer } from 'node:http';
import { writeFileSync } from 'node:fs';
// 429 on one port, 402 on another: the two answers a live service gives a caller it will not scan for.
const out = {};
for (const [name, status, body] of [['limit', 429, { error: 'rate_limited', retry_after_seconds: 30 }], ['credits', 402, { error: 'insufficient_credits' }]]) {
  const s = createServer((req, res) => { req.resume(); req.on('end', () => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body))); });
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  out[name] = s.address().port;
}
writeFileSync(process.argv[2], JSON.stringify(out));
