/**
 * The on-disk half of the check, and the only part that works with the network
 * switched off.
 *
 * A pre-install check answers a question about an identity: this name at this
 * version. It cannot answer a question about the bytes, because the bytes are
 * not here yet. After the install, they are. Re-hashing what actually landed
 * and comparing it to the hash that was checked is what catches drift between
 * the check and the use.
 *
 * The algorithm is reproduced exactly from the Lazaretto API so the two agree:
 * an order-independent sha256 over sorted per-file hashes (see the API's
 * canonicalArtifactHash, and skill/lazaretto-verify.mjs in the API repo).
 * Changing it here without changing it there makes every comparison fail.
 */
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

/** Never part of a scanned artifact, so never part of the hash. */
const IGNORE = new Set(['.git', 'node_modules', '.DS_Store']);

export function sha256Hex(input) {
  return createHash('sha256').update(input).digest('hex');
}

/** The exact server algorithm. */
export function canonicalArtifactHash(files) {
  if (files.length === 1) {
    return `sha256:${sha256Hex(Buffer.from(files[0].content, 'utf8'))}`;
  }
  const lines = files
    .map((f) => `${f.path}\n${sha256Hex(Buffer.from(f.content, 'utf8'))}`)
    .sort();
  return `sha256:${sha256Hex(Buffer.from(`${lines.join('\n')}\n`, 'utf8'))}`;
}

/** Every file under `dir`, as `{ path, content }`. */
export function readTree(dir) {
  const out = [];
  const walk = (abs, rel) => {
    for (const name of readdirSync(abs)) {
      if (IGNORE.has(name)) continue;
      const childAbs = path.join(abs, name);
      const childRel = rel ? `${rel}/${name}` : name;
      const st = statSync(childAbs);
      if (st.isDirectory()) walk(childAbs, childRel);
      else if (st.isFile()) out.push({ path: childRel, content: readFileSync(childAbs, 'utf8') });
    }
  };
  walk(dir, '');
  return out;
}

/** Hash a file or a directory the way the API would. */
export function hashPath(target) {
  const st = statSync(target);
  if (st.isFile()) {
    return canonicalArtifactHash([{ path: path.basename(target), content: readFileSync(target, 'utf8') }]);
  }
  return canonicalArtifactHash(readTree(target));
}

/** Does what landed on disk match the hash that was checked? */
export function verifyInstalled(target, expectedTargetHash) {
  const actual = hashPath(target);
  const expected = expectedTargetHash.startsWith('sha256:') ? expectedTargetHash : `sha256:${expectedTargetHash}`;
  return {
    match: actual === expected,
    actual,
    expected,
    message:
      actual === expected
        ? 'Match: what is on disk is what was checked.'
        : 'Mismatch: what is on disk is not what was checked. Treat it as unchecked.',
  };
}
