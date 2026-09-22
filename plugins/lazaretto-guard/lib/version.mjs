/**
 * The one place the client version comes from.
 *
 * `.claude-plugin/plugin.json` is the version people actually install, so it is
 * the version that goes on the wire. The hook and the CLI both read it from
 * here rather than carrying a copy, because a copy drifts and nothing notices.
 *
 * Reading it cannot throw. This module is imported at the top of the hook, and
 * an import-time throw there would be a non-zero exit, which the hook is not
 * allowed to do. An unreadable manifest gives a tag with no version on it
 * instead of a made-up one.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/** The plugin manifest, resolved from this file rather than from the cwd. */
export const MANIFEST_PATH = fileURLToPath(new URL('../.claude-plugin/plugin.json', import.meta.url));

/** The client name, without a version. Also the fallback tag. */
export const CLIENT_NAME = 'lazaretto-guard';

function readVersion() {
  try {
    const parsed = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'));
    return typeof parsed?.version === 'string' ? parsed.version : '';
  } catch {
    return '';
  }
}

/** The version in the manifest, or '' if it could not be read. */
export const VERSION = readVersion();

/** What the API sees: `lazaretto-guard/<version>`. */
export const CLIENT_TAG = VERSION === '' ? CLIENT_NAME : `${CLIENT_NAME}/${VERSION}`;
