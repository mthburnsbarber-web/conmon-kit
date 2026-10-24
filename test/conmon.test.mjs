import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { loadConfig, report, scan } from '../conmon.mjs';
import { parseCsv } from '../poam.mjs';

function project() {
  const root = mkdtempSync(join(tmpdir(), 'conmon-'));
  mkdirSync(join(root, 'api'));
  writeFileSync(join(root, 'inventory.json'), JSON.stringify({ assets: [
    { id: 'INV-APP-01', name: 'API', kind: 'code', source: 'api', url: 'https://app.example.com/' },
    { id: 'INV-ADM-01', name: 'Admin laptop', kind: 'workstation' }] }));
  writeFileSync(join(root, 'conmon.json'), JSON.stringify({ system: 'Example App', inventory: 'inventory.json',
    scans: { trivy: { api: 'api' }, nuclei: { url: 'https://app.example.com/' }, testssl: { url: 'https://app.example.com/' }, dependabot: { repo: 'example/app' } } }));
  return { root, cfg: loadConfig(join(root, 'conmon.json')) };
}
const now = new Date(2026, 10, 15, 2, 30);

test('config paths resolve beside the config file', () => {
  const { root, cfg } = project();
  assert.equal(cfg.trivyPaths.api, join(root, 'api'));
  assert.equal(cfg.inventoryData.assets.length, 2);
});

test('with no scanner installed every configured scan is recorded as skipped and the reports still show the gaps', async () => {
  const { root, cfg } = project();
  const r = await scan(join(root, 'evidence'), cfg, { has: () => false, run: () => ({ status: 1, stdout: '', stderr: '' }), env: {}, now });
  assert.equal(r.dir, join(root, 'evidence', '2026-11'));
  const files = readdirSync(r.dir).sort();
  for (const f of ['trivy-api-2026-11-15.skipped', 'nuclei-2026-11-15.skipped', 'testssl-2026-11-15.skipped', 'dependabot-2026-11-15.skipped', 'scanner-versions-2026-11-15.txt', 'poam-2026-11-15.csv', 'scan-summary-2026-11-15.md', 'scan-results-2026-11-15.csv']) assert.ok(files.includes(f), f);
  const poam = parseCsv(readFileSync(join(r.dir, 'poam-2026-11-15.csv'), 'utf8'));
  assert.deepEqual(poam.map((p) => p['Weakness Name']), ['No source scan: API', 'No web application scan: https://app.example.com/', 'No workstation check: Admin laptop'],
    'the inventory names a workstation that was not checked');
  assert.match(readFileSync(join(r.dir, 'scan-summary-2026-11-15.md'), 'utf8'), /Not run this month: .*nuclei-2026-11-15\.skipped/);
});

test('scanner output becomes POA&M items; a signed-in web scan never writes the cookie into the evidence', async () => {
  const { root, cfg } = project();
  const calls = [];
  const run = (cmd, args) => {
    calls.push([cmd, ...args]);
    const output = args[args.indexOf(cmd === 'nuclei' ? '-o' : '--output') + 1];
    if (cmd === 'trivy' && args[0] === 'fs') writeFileSync(output, JSON.stringify({ Results: [{ Target: 'package-lock.json', Vulnerabilities: [{ VulnerabilityID: 'CVE-2026-0002', PkgName: 'lib', Severity: 'CRITICAL', Title: 'RCE', FixedVersion: '1.2.3' }] }] }));
    if (cmd === 'nuclei' && args.includes('-u')) writeFileSync(output, JSON.stringify({ 'template-id': 'git-config', 'matched-at': 'https://app.example.com/.git/config', info: { name: 'Git config exposed', severity: 'medium' } }) + '\n');
    if (cmd === 'gh') return { status: 0, stdout: '[[]]', stderr: '' };
    return { status: 0, stdout: `${cmd} 1.0`, stderr: '' };
  };
  const cookie = 'session=very-secret-value';
  const r = await scan(join(root, 'evidence'), cfg, { has: (c) => c !== 'testssl.sh', run, env: { SCAN_COOKIE: cookie }, now });
  const poam = parseCsv(readFileSync(join(r.dir, 'poam-2026-11-15.csv'), 'utf8'));
  assert.deepEqual(poam.map((p) => [p['Weakness Name'], p['Original Risk Rating'], p['Scheduled Completion Date']]),
    [['lib CVE-2026-0002', 'High', '2026-12-15'], ['Web: git-config', 'Moderate', '2027-02-13'], ['No workstation check: Admin laptop', 'Moderate', '2027-02-13']]);
  assert.deepEqual(r.open, { High: 1, Moderate: 2, Low: 0 });
  assert.equal(readFileSync(join(r.dir, 'nuclei-2026-11-15.auth'), 'utf8'), 'authenticated\n');
  assert.ok(calls.some((c) => c[0] === 'nuclei' && c.includes(`Cookie: ${cookie}`)), 'the cookie goes to the scanner');
  for (const f of readdirSync(r.dir)) assert.ok(!readFileSync(join(r.dir, f), 'utf8').includes('very-secret-value'), `${f} must not hold the cookie`);
  assert.ok(existsSync(join(r.dir, 'testssl-2026-11-15.skipped')));
  assert.match(readFileSync(join(r.dir, 'scan-results-2026-11-15.csv'), 'utf8'), /"trivy","api","package-lock.json","vulnerability","CVE-2026-0002"/);

  // Next month the vulnerability is fixed: Trivy runs again and no longer finds it, so the item closes.
  const december = new Date(2026, 11, 15, 2, 30);
  const clean = (cmd, args) => { if (cmd === 'trivy' && args[0] === 'fs') { writeFileSync(args[args.indexOf('--output') + 1], '{"Results":[]}'); return { status: 0, stdout: '', stderr: '' }; } return run(cmd, args); };
  const next = await scan(join(root, 'evidence'), cfg, { has: (c) => c !== 'testssl.sh', run: clean, env: { SCAN_COOKIE: cookie }, now: december });
  const after = parseCsv(readFileSync(join(next.dir, 'poam-2026-12-15.csv'), 'utf8'));
  assert.deepEqual(after.map((p) => [p['POA&M ID'], p.Status]), [['POAM-0002', 'Open'], ['POAM-0003', 'Open'], ['POAM-0001', 'Closed']]);
});

test('report rebuilds the month from the files already there', () => {
  const { root, cfg } = project();
  const dir = join(root, 'evidence', '2026-11');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'check-cloudflare-2026-11-15.json'), JSON.stringify({ source: 'Cloudflare settings check', rows: [{ control: 'SC-8', check: 'HSTS', expected: 'on', actual: 'off', pass: 'FAIL' }] }));
  const r = report(dir, cfg, { today: '2026-11-16' });
  assert.deepEqual(r.files, ['scan-results-2026-11-16.csv', 'scan-summary-2026-11-16.md', 'poam-2026-11-16.csv']);
  assert.equal(r.open.Moderate, 4, 'HSTS plus three coverage gaps: source scan, web scan, workstation');
});
