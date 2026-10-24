import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { buildPoam, coverage, coverageItems, dependabotItems, gapItems, nucleiItems, parseCsv, toCsv, trivyItems } from '../poam.mjs';

const fresh = (...months) => { const root = mkdtempSync(join(tmpdir(), 'poam-')); for (const m of months) mkdirSync(join(root, m)); return root; };
const check = (rows) => JSON.stringify({ source: 'Cloudflare settings check', asset: 'example.com', rows });
const fail = (name) => ({ control: 'SC-8', check: name, expected: 'on', actual: 'off', pass: 'FAIL' });
const config = { system: 'Example App', pointOfContact: 'Jane Doe' };

test('items keep their ID and first detection date across months; new findings get the next ID; fixed ones close', () => {
  const root = fresh('2026-10', '2026-11');
  writeFileSync(join(root, '2026-10', 'check-cloudflare-2026-10-23.json'), check([fail('Always Use HTTPS'), fail('HSTS')]));
  const october = buildPoam({ dir: join(root, '2026-10'), today: '2026-10-23', config });
  writeFileSync(join(root, '2026-10', 'poam-2026-10-23.csv'), toCsv(october, config));
  assert.deepEqual(october.map((i) => [i.id, i.name, i.detected, i.due]), [['POAM-0001', 'Always Use HTTPS', '2026-10-23', '2027-01-21'], ['POAM-0002', 'HSTS', '2026-10-23', '2027-01-21']]);

  writeFileSync(join(root, '2026-11', 'check-cloudflare-2026-11-23.json'), check([fail('HSTS'), fail('DNSSEC')]));
  const november = buildPoam({ dir: join(root, '2026-11'), today: '2026-11-23', config });
  const byName = Object.fromEntries(november.map((i) => [i.name, i]));
  assert.equal(byName.HSTS.id, 'POAM-0002');
  assert.equal(byName.HSTS.detected, '2026-10-23', 'the deadline runs from first detection');
  assert.equal(byName.HSTS.due, '2027-01-21');
  assert.equal(byName.DNSSEC.id, 'POAM-0003');
  assert.equal(byName['Always Use HTTPS'].status, 'Closed', 'a fixed weakness is closed, not dropped');
  const csv = parseCsv(toCsv(november, config));
  assert.equal(csv.length, 3);
  assert.equal(csv[0]['Point of Contact'], 'Jane Doe');
  assert.equal(csv[0].Boundary, 'Example App');
});

test('a same-day re-run keeps IDs and closes what was fixed; items closed this month stay listed', () => {
  const dir = join(fresh('2026-10'), '2026-10');
  writeFileSync(join(dir, 'check-cloudflare-2026-10-23.json'), check([fail('Always Use HTTPS'), fail('HSTS')]));
  writeFileSync(join(dir, 'poam-2026-10-23.csv'), toCsv(buildPoam({ dir, today: '2026-10-23', config }), config));
  writeFileSync(join(dir, 'check-cloudflare-2026-10-23.json'), check([fail('HSTS')]));
  const evening = buildPoam({ dir, today: '2026-10-23', config });
  assert.deepEqual(evening.map((i) => [i.id, i.name, i.status]), [['POAM-0002', 'HSTS', 'Open'], ['POAM-0001', 'Always Use HTTPS', 'Closed']]);
  writeFileSync(join(dir, 'poam-2026-10-23.csv'), toCsv(evening, config));
  assert.deepEqual(buildPoam({ dir, today: '2026-10-29', config }).map((i) => [i.id, i.status, i.statusDate]), [['POAM-0002', 'Open', '2026-10-29'], ['POAM-0001', 'Closed', '2026-10-23']]);
});

test('TLS items keep their ID when the next scan reaches another address; lows are listed once per weakness', () => {
  const dir = join(fresh('2026-10'), '2026-10');
  writeFileSync(join(dir, 'poam-2026-10-23.csv'), toCsv([{ id: 'POAM-0001', controls: 'SC-8, SC-13', name: 'TLS: BREACH', description: 'd', source: 'testssl.sh', sourceId: 'BREACH',
    asset: 'example.com/104.16.1.1:443', detected: '2026-10-23', risk: 'Moderate', due: '2027-01-21', plan: 'p', status: 'Open', statusDate: '2026-10-23', boundary: 'Example App' }], config));
  const tls = (id, severity) => ({ id, ip: 'example.com/104.16.2.2', port: '443', severity, finding: 'potentially vulnerable' });
  writeFileSync(join(dir, 'testssl-2026-10-23.json'), JSON.stringify([tls('BREACH', 'MEDIUM'), tls('LUCKY13', 'LOW'), tls('TLS1_3', 'OK'),
    tls('cipher-tls1_2_xc009', 'LOW'), tls('DNS_CAArecord <hostCert#1>', 'LOW'), tls('DNS_CAArecord <hostCert#2>', 'LOW')]));
  assert.deepEqual(buildPoam({ dir, today: '2026-10-23', config }).map((i) => [i.id, i.name, i.asset, i.risk]),
    [['POAM-0001', 'TLS: BREACH', 'example.com:443', 'Moderate'], ['POAM-0002', 'TLS: LUCKY13', 'example.com:443', 'Low'], ['POAM-0003', 'TLS: DNS_CAArecord', 'example.com:443', 'Low']]);
});

test('an item stays open when its scanner did not run this month: a missing scan is not a fix', () => {
  const root = fresh('2026-10', '2026-11');
  const trivy = { Results: [{ Target: 'package-lock.json', Vulnerabilities: [{ VulnerabilityID: 'CVE-2026-0001', PkgName: 'x', Severity: 'HIGH', Title: 't', FixedVersion: '2' }] }] };
  writeFileSync(join(root, '2026-10', 'trivy-api-2026-10-23.json'), JSON.stringify(trivy));
  writeFileSync(join(root, '2026-10', 'poam-2026-10-23.csv'), toCsv(buildPoam({ dir: join(root, '2026-10'), today: '2026-10-23', config }), config));
  writeFileSync(join(root, '2026-11', 'check-cloudflare-2026-11-23.json'), check([]));
  assert.deepEqual(buildPoam({ dir: join(root, '2026-11'), today: '2026-11-23', config }).map((i) => [i.id, i.status, i.statusDate, i.sourceId]), [['POAM-0001', 'Open', '2026-10-23', 'CVE-2026-0001']]);
});

test('web findings and scan coverage gaps against the inventory', () => {
  const line = (id, severity) => JSON.stringify({ 'template-id': id, 'matched-at': 'https://app.example.com/', info: { name: id, severity } });
  assert.deepEqual(nucleiItems([line('tech-detect', 'info'), line('cors-misconfig', 'medium'), line('cors-misconfig', 'medium')].join('\n'), '2026-11-23').map((i) => [i.name, i.risk]), [['Web: cors-misconfig', 'Moderate']]);
  const dir = mkdtempSync(join(tmpdir(), 'cov-'));
  writeFileSync(join(dir, 'trivy-api-2026-11-23.json'), '{}');
  writeFileSync(join(dir, 'nuclei-2026-11-23.jsonl'), '');
  writeFileSync(join(dir, 'nuclei-2026-11-23.auth'), 'unauthenticated\n');
  const inventory = { assets: [
    { id: 'A-1', name: 'api', kind: 'code', source: 'api', url: 'https://app.example.com/' },
    { id: 'A-2', name: 'jobs', kind: 'code', worker: 'jobs' },
    { id: 'A-3', name: 'database', kind: 'managed' },
    { id: 'A-4', name: 'admin laptop', kind: 'workstation' }
  ] };
  assert.deepEqual(coverageItems(coverage(dir, inventory), '2026-11-23', config).map((i) => [i.asset, i.name]),
    [['A-1', 'Unauthenticated web application scan: https://app.example.com/'], ['A-2', 'No source scan: jobs'], ['A-4', 'No workstation check: admin laptop']]);
  writeFileSync(join(dir, 'nuclei-2026-11-23.auth'), 'authenticated\n');
  writeFileSync(join(dir, 'workstation-2026-11-23.txt'), 'ok');
  writeFileSync(join(dir, 'trivy-deployed-jobs-2026-11-23.json'), '{}');
  const gaps = coverageItems(coverage(dir, inventory), '2026-11-23', config);
  assert.deepEqual(gaps.map((i) => i.asset), ['A-2'], 'a signed-in web scan and a workstation check close their gaps');
  assert.match(gaps[0].description, /scanned for secrets and misconfiguration, but its dependencies are not/);
});

test('a group asset is deployed-code scanned only when every member was; any check file becomes items', () => {
  const dir = mkdtempSync(join(tmpdir(), 'group-'));
  writeFileSync(join(dir, 'trivy-deployed-relay-2026-11-23.json'), '{}');
  const group = { assets: [{ id: 'G-1', name: 'helper Workers', kind: 'code', members: ['relay', 'voice'] }] };
  assert.ok(!coverage(dir, group)[0].scans.includes('Trivy deployed-code scan'));
  writeFileSync(join(dir, 'trivy-deployed-voice-2026-11-23.json'), '{}');
  assert.ok(coverage(dir, group)[0].scans.includes('Trivy deployed-code scan'));
  writeFileSync(join(dir, 'check-backups-2026-11-23.json'), JSON.stringify({ source: 'Backup check', rows: [
    { control: 'CP-9', check: 'Nightly database export', expected: 'present', actual: 'missing since 2026-11-20', pass: 'FAIL', risk: 'High', asset: 'backups' },
    { control: 'CP-6', check: 'Bucket location', expected: 'us', actual: 'us', pass: 'PASS' }] }));
  assert.deepEqual(buildPoam({ dir, today: '2026-11-23', config }).map((i) => [i.source, i.name, i.risk, i.asset]), [['Backup check', 'Nightly database export', 'High', 'backups']]);
});

test('gap assessment rows that are not Met become items, with priority as risk', () => {
  const md = '| # | Control | Status | Evidence | What closes it | Owner | Priority |\n|---|---|---|---|---|---|---|\n'
    + '| 1 | AC-2 Account management | **Met** | review | — | Security | — |\n| 2 | CP-4 Contingency plan testing | Not met | none | Test a restore | Ops | P1 |\n| 3 | AT-2 Training | Partially met | 2 of 3 | Train one | Security | P3 |\n';
  assert.deepEqual(gapItems(md, '2026-11-23', { system: 'Example App' }).map((i) => [i.controls, i.risk, i.plan]), [['CP-4', 'High', 'Test a restore (owner: Ops)'], ['AT-2', 'Low', 'Train one (owner: Security)']]);
});

test('boundary paths, custom deadlines and ID prefix; only failing misconfigurations count', () => {
  const alerts = [[
    { created_at: '2026-11-01T00:00:00Z', dependency: { manifest_path: 'services/api/package-lock.json', package: { name: 'a' } }, security_advisory: { ghsa_id: 'GHSA-1', cve_id: 'CVE-2026-1', severity: 'critical', summary: 's' } },
    { created_at: '2026-11-02T00:00:00Z', dependency: { manifest_path: 'tools/old/package-lock.json', package: { name: 'b' } }, security_advisory: { ghsa_id: 'GHSA-2', severity: 'low', summary: 's' } }
  ]];
  const cfg = { system: 'Example App', boundaryPaths: ['services/'] };
  assert.deepEqual(dependabotItems(alerts, '2026-11-23', { ...cfg, idPrefix: 'POAM', deadlines: {} }).map((i) => [i.risk, i.boundary, i.sourceId, i.detected]),
    [['High', 'Example App', 'CVE-2026-1', '2026-11-01'], ['Low', 'Outside boundary', 'GHSA-2', '2026-11-02']]);
  const report = { Results: [{ Target: 'Dockerfile', Misconfigurations: [{ ID: 'DS002', AVDID: 'AVD-DS-0002', Severity: 'HIGH', Status: 'FAIL', Title: 'root user' }, { ID: 'DS001', Severity: 'MEDIUM', Status: 'PASS' }] }] };
  assert.deepEqual(trivyItems(report, 'api', '2026-11-23').map((i) => [i.name, i.risk, i.sourceId]), [['Misconfiguration: DS002', 'High', 'AVD-DS-0002']]);
  const dir = mkdtempSync(join(tmpdir(), 'deadline-'));
  writeFileSync(join(dir, 'trivy-api-2026-11-23.json'), JSON.stringify(report));
  const [item] = buildPoam({ dir, today: '2026-11-23', config: { system: 'Example App', idPrefix: 'EX', deadlines: { High: 15 } } });
  assert.deepEqual([item.id, item.due], ['EX-0001', '2026-12-08']);
});
