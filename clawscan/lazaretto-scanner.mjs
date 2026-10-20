#!/usr/bin/env node
/**
 * Lazaretto as a ClawScan command scanner.
 *
 * ClawScan's documented path for an outside scanner is a user-defined command
 * in a custom profile (docs/scanners.md, "Profile scanner configuration"): it
 * runs `command` with {{target}}, captures stdout as the scanner's raw JSON
 * evidence, and applies gate rules to it. This file is that command.
 *
 *   node lazaretto-scanner.mjs <target>
 *
 * <target> is either:
 *   - a local skill directory: its SKILL.md is sent as inline content, and
 *     every other file is listed under `not_scanned`, so a gate never reads a
 *     partial scan as a whole one;
 *   - a published ClawHub skill, `owner/name` or `owner/name@version`: the
 *     whole package is fetched and scanned server side.
 *
 * Output is one JSON object on stdout. Exit 0 means a scan completed (whatever
 * it found); exit 1 means no scan result exists, and the JSON says why. That
 * split is what ClawScan asks adapters to report explicitly: a failed or
 * skipped scan must never look like a clean one.
 *
 * Environment: LAZARETTO_API_KEY (required, declare it under secretEnv so it
 * never lands in a flag or an artifact), LAZARETTO_API (optional base URL).
 * Dependencies: none. It reads files and makes one HTTPS request.
 */
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';

const API = (process.env.LAZARETTO_API ?? 'https://lazaretto.dev').replace(/\/+$/, '');
const TIMEOUT_MS = 60_000;
const CLAWHUB_REF = /^[\w.-]+\/[\w./-]+(@[\w.-]+)?$/;
const IGNORE = new Set(['.git', 'node_modules', '.DS_Store']);

function emit(obj, code) {
  process.stdout.write(`${JSON.stringify(obj, null, 2)}\n`);
  process.exit(code);
}

function fail(reason, extra = {}) {
  emit({ scanner: 'lazaretto', status: 'error', reason, not_an_all_clear: true, ...extra }, 1);
}

function listFiles(dir) {
  const out = [];
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      if (IGNORE.has(name)) continue;
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else out.push(relative(dir, p));
    }
  };
  walk(dir);
  return out.sort();
}

function buildRequest(target) {
  if (existsSync(target) && statSync(target).isDirectory()) {
    const skillPath = join(target, 'SKILL.md');
    if (!existsSync(skillPath)) fail('no SKILL.md in the target directory', { target });
    const content = readFileSync(skillPath, 'utf8');
    const others = listFiles(target).filter((f) => f !== 'SKILL.md');
    return {
      // The name selects which rules run; without it a SKILL.md is not read as markdown.
      body: { target: { type: 'inline', content, name: 'SKILL.md' }, depth: 'full' },
      scanned: ['SKILL.md'],
      notScanned: others,
      mode: 'local',
    };
  }
  if (CLAWHUB_REF.test(target)) {
    return { body: { target: { type: 'clawhub_skill', ref: target }, depth: 'full' }, scanned: 'whole package', notScanned: [], mode: 'clawhub' };
  }
  fail('target is neither a local skill directory nor a ClawHub owner/name reference', { target });
}

async function main() {
  const target = process.argv[2];
  if (!target) fail('usage: lazaretto-scanner.mjs <skill-dir | owner/name[@version]>');
  const key = process.env.LAZARETTO_API_KEY?.trim();
  if (!key) fail('LAZARETTO_API_KEY is not set. A free key: curl -s -X POST https://lazaretto.dev/v1/trial');

  const req = buildRequest(target);
  let res;
  try {
    res = await fetch(`${API}/v1/scan`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': key, 'user-agent': 'lazaretto-clawscan/0.1.0' },
      body: JSON.stringify(req.body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (e) {
    fail('scan service unreachable or timed out', { detail: String(e?.message ?? e) });
  }

  let report;
  try {
    report = await res.json();
  } catch {
    fail(`scan service answered HTTP ${res.status} with a body that is not JSON`);
  }
  if (res.status === 402 || res.status === 429) {
    // Out of credits or rate limited: a scan that did not happen, stated as such.
    fail(res.status === 402 ? 'no scan credits left on this key' : 'rate limited', { http_status: res.status, retry_after_seconds: report?.retry_after_seconds ?? null });
  }
  if (!res.ok) fail(`scan service answered HTTP ${res.status}`, { error: report?.error ?? null, detail: report?.detail ?? null });
  if (report?.verdict === 'error') fail('the scan itself errored; nothing was billed', { detail: report?.detail ?? null });

  emit(
    {
      scanner: 'lazaretto',
      status: 'ok',
      mode: req.mode,
      target,
      verdict: report.verdict,
      risk: report.risk ?? null,
      findings: (report.findings ?? []).map((f) => ({
        rule_id: f.rule_id ?? f.id ?? null,
        severity: f.severity ?? null,
        file: f.file ?? f.path ?? null,
        line: f.line ?? null,
        detail: f.detail ?? f.message ?? null,
      })),
      scanned: req.scanned,
      // Files a local scan did not read. Non-empty means a clean verdict covers
      // SKILL.md only, not the skill as a whole.
      not_scanned: req.notScanned,
      complete: req.notScanned.length === 0,
      target_hash: report.target_hash ?? null,
      scan_id: report.scan_id ?? null,
      report_url: report.report_url ?? null,
      disclaimer: 'Signals, not a warranty. A clean verdict means these rules found nothing, not that the skill is harmless.',
    },
    0,
  );
}

main();
