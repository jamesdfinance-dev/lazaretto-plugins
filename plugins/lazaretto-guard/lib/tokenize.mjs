/**
 * A deliberately small shell tokenizer.
 *
 * This is NOT a shell. It never executes anything. Its only job is to turn a
 * command string into segments of plain tokens so the parser can look for
 * pinned package specs. Anything it cannot read confidently it refuses, and a
 * refusal means the hook stays silent. Guessing at a command we do not
 * understand is how a guard earns an uninstall.
 */

/** Characters that end one command and begin another. */
const OPERATORS = new Set(['&', '|', ';', '\n']);

/** Nothing worth parsing is longer than this; refuse rather than grind. */
const MAX_COMMAND_CHARS = 20_000;

/**
 * Split a command string into segments of tokens.
 *
 * Returns `{ ok: false, segments: [] }` when the command contains substitution
 * we cannot resolve (`$(...)` or backticks) or an unterminated quote, because
 * in those cases the tokens we would produce are not the tokens the shell will
 * run.
 */
export function tokenize(command) {
  if (typeof command !== 'string') return { ok: false, segments: [] };
  const text = command.trim();
  if (text === '' || text.length > MAX_COMMAND_CHARS) return { ok: false, segments: [] };
  // Command substitution means the real argv is not knowable from the text.
  if (text.includes('$(') || text.includes('`')) return { ok: false, segments: [] };

  const segments = [];
  let current = [];
  let token = '';
  let started = false;
  let i = 0;

  const endToken = () => {
    if (started) {
      current.push(token);
      token = '';
      started = false;
    }
  };
  const endSegment = () => {
    endToken();
    if (current.length > 0) segments.push(current);
    current = [];
  };

  while (i < text.length) {
    const c = text[i];

    if (c === '\\') {
      if (i + 1 >= text.length) return { ok: false, segments: [] };
      token += text[i + 1];
      started = true;
      i += 2;
      continue;
    }

    if (c === "'") {
      const end = text.indexOf("'", i + 1);
      if (end === -1) return { ok: false, segments: [] };
      token += text.slice(i + 1, end);
      started = true;
      i = end + 1;
      continue;
    }

    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < text.length && text[j] !== '"') {
        if (text[j] === '\\' && j + 1 < text.length) {
          out += text[j + 1];
          j += 2;
          continue;
        }
        out += text[j];
        j += 1;
      }
      if (j >= text.length) return { ok: false, segments: [] };
      token += out;
      started = true;
      i = j + 1;
      continue;
    }

    if (c === ' ' || c === '\t' || c === '\r') {
      endToken();
      i += 1;
      continue;
    }

    // A '#' only opens a comment at the start of a word.
    if (c === '#' && !started) {
      const nl = text.indexOf('\n', i);
      i = nl === -1 ? text.length : nl;
      continue;
    }

    if (OPERATORS.has(c)) {
      endSegment();
      while (i < text.length && OPERATORS.has(text[i])) i += 1;
      continue;
    }

    token += c;
    started = true;
    i += 1;
  }

  endSegment();
  return { ok: true, segments };
}
