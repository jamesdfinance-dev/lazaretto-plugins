/**
 * Where this plugin keeps what it saves between runs: the free key and the
 * tool pins, both under `$XDG_CONFIG_HOME/lazaretto` (default `~/.config`).
 */
import { homedir } from 'node:os';
import { join } from 'node:path';

export function configDir(env = process.env) {
  const base = env.XDG_CONFIG_HOME && env.XDG_CONFIG_HOME !== '' ? env.XDG_CONFIG_HOME : join(homedir(), '.config');
  return join(base, 'lazaretto');
}
