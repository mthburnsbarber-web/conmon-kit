// POA&M rules: one month's scan folder (and, optionally, a gap assessment) to Plan of Action and Milestones items.
// Each open weakness gets an ID, its controls, the detector, the asset, the risk rating and a remediation deadline counted
// from the date it was FIRST found (by default high 30 days, moderate 90, low 180). Items keep their ID and first
// detection date from the newest earlier POA&M in the evidence folder. An earlier item that is no longer found is Closed,
// but only when the scanner that found it ran again: a scan that did not run is not a fix. Scan coverage gaps against
// the boundary inventory are items too, because programs reject scans that skip boundary components or run signed out.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

export const DEFAULTS = { system: 'System', organization: '', pointOfContact: '', idPrefix: 'POAM', deadlines: { High: 30, Moderate: 90, Low: 180 }, boundaryPaths: null };
export const COLUMNS = ['POA&M ID', 'Controls', 'Weakness Name', 'Weakness Description', 'Weakness Detector Source', 'Weakness Source Identifier',
  'Asset Identifier', 'Point of Contact', 'Original Detection Date', 'Original Risk Rating', 'Scheduled Completion Date', 'Overall Remediation Plan',
  'Status', 'Status Date', 'Boundary'];

export const settings = (config = {}) => ({ ...DEFAULTS, ...config, deadlines: { ...DEFAULTS.deadlines, ...config.deadlines } });
// Dates are local calendar days, the same days the scan files are named with.
export const localDay = (date = new Date()) => date.toLocaleDateString('en-CA');
const addDays = (day, n) => new Date(Date.parse(day + 'T00:00:00Z') + n * 86400000).toISOString().slice(0, 10);
const latest = (dir, prefix, ext) => readdirSync(dir).filter((f) => f.startsWith(prefix) && f.endsWith(ext)).sort().pop();
const risk3 = (sev) => (/^(critical|high)$/i.test(sev) ? 'High' : /^(medium|moderate)$/i.test(sev) ? 'Moderate' : 'Low');

export function gapItems(markdown, day, cfg = settings()) {
  // Rows of gap assessment tables whose status is not Met. Columns: [#,] Control, Status, Evidence, Fix, Owner, Priority.
  const items = [];
  for (const line of markdown.split('\n')) {
    const cells = line.split('|').slice(1, -1).map((c) => c.trim());
    if (cells.length < 6 || !/^[A-Z]{2}-\d/.test(cells[cells.length === 7 ? 1 : 0])) continue;
    const [control, status, evidence, fix, owner, priority] = cells.length === 7 ? cells.slice(1) : cells;
    if (/^\**Met\b/i.test(status) || priority === '—' || priority === '-') continue;
    items.push({ controls: control.split(' ')[0], name: control, description: `${status}: ${evidence}`, source: 'Gap assessment', sourceId: control.split(' ')[0],
      asset: cfg.system, detected: day, risk: priority === 'P1' ? 'High' : priority === 'P3' ? 'Low' : 'Moderate', plan: `${fix} (owner: ${owner})`, boundary: cfg.system });
  }
  return items;
}

// A check file (check-<name>-<date>.json): { source?, asset?, rows: [{ control, check, expected, actual, pass, risk?, asset?, plan? }] }.
// The Cloudflare checks write this format; so can any check of your own.
export function checkItems(json, name, day, cfg = settings()) {
  return (json.rows || []).filter((r) => r.pass === 'FAIL').map((r) => ({ controls: r.control, name: r.check, description: `Expected ${r.expected}; found ${r.actual}`,
    source: json.source || `${name} check`, sourceId: '', asset: r.asset || json.asset || name, detected: day, risk: r.risk || 'Moderate',
    plan: r.plan || 'Change it to the baseline value; the next monthly check verifies it.', boundary: cfg.system }));
}

export function dependabotItems(pages, day, cfg = settings()) {
  const inBoundary = (path) => !cfg.boundaryPaths || cfg.boundaryPaths.some((p) => path.startsWith(p));
  return pages.flat().map((a) => {
    const path = a.dependency?.manifest_path || '', adv = a.security_advisory || {};
    return { controls: 'RA-5, SI-2', name: `${a.dependency?.package?.name} ${adv.ghsa_id}`, description: adv.summary || '', source: 'GitHub Dependabot', sourceId: adv.cve_id || adv.ghsa_id || '',
      asset: path, detected: (a.created_at || day).slice(0, 10), risk: risk3(adv.severity), plan: 'Upgrade to the patched version named in the advisory.',
      boundary: inBoundary(path) ? cfg.system : 'Outside boundary' };
  });
}

export function trivyItems(report, component, day, cfg = settings()) {
  const items = [];
  for (const result of report.Results || []) {
    for (const v of result.Vulnerabilities || []) {
      items.push({ controls: 'RA-5, SI-2', name: `${v.PkgName} ${v.VulnerabilityID}`, description: v.Title || '', source: 'Trivy', sourceId: v.VulnerabilityID, asset: `${component}/${result.Target}`,
        detected: day, risk: risk3(v.Severity), plan: v.FixedVersion ? `Upgrade to ${v.FixedVersion}` : 'No fix yet; assess and mitigate', boundary: cfg.system });
    }
    for (const s of result.Secrets || []) {
      items.push({ controls: 'IA-5, SC-28', name: `Secret in source: ${s.RuleID}`, description: s.Title || '', source: 'Trivy', sourceId: s.RuleID, asset: `${component}/${result.Target}:${s.StartLine}`,
        detected: day, risk: 'High', plan: 'Remove the secret from source and rotate it', boundary: cfg.system });
    }
    for (const m of (result.Misconfigurations || []).filter((x) => !x.Status || x.Status === 'FAIL')) {
      items.push({ controls: 'CM-6, CM-7', name: `Misconfiguration: ${m.ID}`, description: m.Title || '', source: 'Trivy', sourceId: m.AVDID || m.ID, asset: `${component}/${result.Target}`,
        detected: day, risk: risk3(m.Severity), plan: m.Resolution || 'Fix the configuration', boundary: cfg.system });
    }
  }
  return items;
}

export function testsslItems(findings, day, cfg = settings()) {
  // Every LOW or worse finding, once per weakness. The asset is the host without the address the scan happened to reach
  // ("example.com/104.16.1.1" changes from scan to scan behind a CDN). Per-cipher rows (cipher-tls1_2_xc009 …) restate the
  // cipherlist_* results, and "<hostCert#2>" repeats a finding for a second certificate, so neither is a separate item.
  const seen = new Set(), items = [];
  for (const f of Array.isArray(findings) ? findings : findings.scanResult || []) {
    const id = String(f?.id || '').replace(/\s*<hostCert#\d+>$/, '');
    if (!['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(f?.severity) || /^cipher-/.test(id) || seen.has(id)) continue;
    seen.add(id);
    items.push({ controls: 'SC-8, SC-13', name: `TLS: ${id}`, description: String(f.finding || '').replace(/\s+/g, ' ').slice(0, 300), source: 'testssl.sh', sourceId: id,
      asset: `${String(f.ip || 'host').split('/')[0]}:${f.port || 443}`, detected: day, risk: risk3(f.severity),
      plan: /^(SSLv2|SSLv3|TLS1|TLS1_1)$|BEAST|POODLE/i.test(id) ? 'Set the minimum TLS version to 1.2'
        : /3DES|SWEET32/i.test(id) ? 'Disable the 3DES cipher suites'
          : /CAA/.test(id) ? 'Add a CAA record naming the certificate authorities you use'
            : /OBSOLETED|LUCKY13|CBC/i.test(id) ? 'Drop the CBC cipher suites (keep AEAD suites on TLS 1.2, or serve TLS 1.3 only)' : 'Assess and mitigate',
      boundary: cfg.system });
  }
  return items;
}

export function nucleiItems(jsonl, day, cfg = settings()) {
  // One item per template and matched URL; informational matches (technology detection) are not weaknesses.
  const seen = new Set(), items = [];
  for (const line of jsonl.split('\n').filter((l) => l.trim())) {
    const f = JSON.parse(line);
    const sev = f.info?.severity, at = f['matched-at'] || f.host || '';
    if (!['low', 'medium', 'high', 'critical'].includes(sev) || seen.has(f['template-id'] + at)) continue;
    seen.add(f['template-id'] + at);
    items.push({ controls: 'RA-5, SI-2', name: `Web: ${f['template-id']}`, description: f.info?.name || '', source: 'nuclei', sourceId: f.info?.classification?.['cve-id']?.[0] || f['template-id'],
      asset: at, detected: day, risk: risk3(sev), plan: f.info?.remediation || 'Assess and fix', boundary: cfg.system });
  }
  return items;
}

export function scanItems(dir, day, cfg = settings()) {
  // Findings from every scanner that ran this month, and the set of scanners that ran (so their old items can close).
  const items = [], ran = new Set();
  const read = (f) => readFileSync(join(dir, f), 'utf8');
  const checks = new Map();
  for (const f of readdirSync(dir).filter((x) => /^check-.+-\d{4}-\d{2}-\d{2}\.json$/.test(x)).sort()) checks.set(f.replace(/^check-|-\d{4}-\d{2}-\d{2}\.json$/g, ''), f);
  for (const [name, f] of checks) {
    const json = JSON.parse(read(f));
    ran.add(json.source || `${name} check`);
    items.push(...checkItems(json, name, day, cfg));
  }
  for (const f of readdirSync(dir).filter((x) => /^trivy-.+-\d{4}-\d{2}-\d{2}\.json$/.test(x))) {
    ran.add('Trivy');
    items.push(...trivyItems(JSON.parse(read(f)), f.replace(/^trivy-|-\d{4}-\d{2}-\d{2}\.json$/g, ''), day, cfg));
  }
  const testssl = latest(dir, 'testssl-', '.json');
  if (testssl) { ran.add('testssl.sh'); items.push(...testsslItems(JSON.parse(read(testssl)), day, cfg)); }
  const web = latest(dir, 'nuclei-', '.jsonl');
  if (web) { ran.add('nuclei'); items.push(...nucleiItems(read(web), day, cfg)); }
  const dependabot = latest(dir, 'dependabot-', '.json');
  if (dependabot) { ran.add('GitHub Dependabot'); items.push(...dependabotItems(JSON.parse(read(dependabot)), day, cfg)); }
  return { items, ran };
}

// Inventory: { assets: [{ id, name, kind: zone|code|managed|workstation, source?, worker?, members?, url? }] }. source is the
// Trivy component that scans the asset's code, worker the Cloudflare Worker it runs as, url its web application scan target.
export function coverage(dir, inventory) {
  const files = readdirSync(dir);
  const has = (prefix, ext) => files.some((f) => f.startsWith(prefix) && f.endsWith(ext));
  const cloudflare = files.filter((f) => /^check-cloudflare-\d{4}-\d{2}-\d{2}\.json$/.test(f)).sort().pop();
  const rows = cloudflare ? JSON.parse(readFileSync(join(dir, cloudflare), 'utf8')).rows || [] : [];
  const web = latest(dir, 'nuclei-', '.jsonl');
  const authFile = web && join(dir, web.replace(/\.jsonl$/, '.auth'));
  const webAuth = !web ? 'none' : existsSync(authFile) ? readFileSync(authFile, 'utf8').trim() : 'unauthenticated';
  return (inventory.assets || []).map((a) => {
    const scans = [];
    if ((a.kind === 'zone' && cloudflare) || (a.worker && rows.some((r) => String(r.check).startsWith(a.worker + ' ')))) scans.push('Cloudflare settings check (API, credentialed)');
    if (a.source && has(`trivy-${a.source}-`, '.json')) scans.push('Trivy source scan');
    // A group counts as deployed-code scanned only when every member Worker's deployed code was.
    const deployed = a.members || (a.worker ? [a.worker] : []);
    if (a.kind === 'code' && deployed.length && deployed.every((w) => has(`trivy-deployed-${w}-`, '.json'))) scans.push('Trivy deployed-code scan');
    if (a.url && web) scans.push(`nuclei web application scan (${webAuth})`);
    if (a.kind === 'zone' && has('testssl-', '.json')) scans.push('testssl.sh TLS scan');
    if (a.kind === 'workstation' && has('workstation-', '.txt')) scans.push('Workstation check');
    return { ...a, scans, webAuth: a.url ? webAuth : '' };
  });
}

export function coverageItems(covered, day, cfg = settings()) {
  const items = [];
  const base = { controls: 'RA-5', source: 'Scan coverage', sourceId: '', detected: day, risk: 'Moderate', boundary: cfg.system };
  for (const a of covered) {
    if (a.kind === 'code' && !a.scans.includes('Trivy source scan')) {
      // A deployed-code scan finds secrets and misconfiguration, but a bundle has no package manifest to check.
      const description = a.scans.includes('Trivy deployed-code scan')
        ? 'The deployed code is scanned for secrets and misconfiguration, but its dependencies are not: a bundle has no package manifest and its source is not in the monthly scan'
        : 'Code in the boundary is not in the monthly scan; every boundary component belongs in every scan';
      items.push({ ...base, name: `No source scan: ${a.name}`, asset: a.id, description, plan: "Add the component's source to the monthly Trivy scan" });
    }
    if (a.url && a.webAuth !== 'authenticated') {
      items.push({ ...base, name: `${a.webAuth === 'none' ? 'No' : 'Unauthenticated'} web application scan: ${a.url}`, asset: a.id,
        description: 'Programs such as FedRAMP and GovRAMP expect authenticated scans unless an exception was granted', plan: 'Run the monthly scan with SCAN_COOKIE set from a dedicated scan account' });
    }
    if (a.kind === 'workstation' && !a.scans.length) {
      items.push({ ...base, name: `No workstation check: ${a.name}`, asset: a.id, description: 'The administrator workstation was not checked this month', plan: 'Run the monthly scan on the administrator workstation' });
    }
  }
  return items;
}

export function parseCsv(text) {
  const rows = [];
  let row = [], cell = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; } else if (c === '"') quoted = false; else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(cell); cell = ''; } else if (c === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; } else if (c !== '\r') cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  const [head, ...body] = rows;
  return body.filter((r) => r.length === head.length).map((r) => Object.fromEntries(head.map((h, i) => [h, r[i]])));
}

// The address part of a TLS asset ("example.com/104.16.1.1:443") changes between scans; compare without it.
const assetKey = (asset) => String(asset).replace(/^([^/]+)\/[\d.:a-f]+(:\d+)$/i, '$1$2');
const keyOf = (it) => [it.source, it.controls, it.name, assetKey(it.asset)].join('|');

export function previousPoam(dir, today) {
  // The newest poam-<date>.csv dated today or earlier, in this month's folder or an earlier month's folder beside it. A
  // re-run on the same day (say, after a fix is verified) carries forward from that day's earlier run, so IDs stay put.
  const root = dirname(dir), files = [];
  for (const month of readdirSync(root).filter((m) => /^\d{4}-\d{2}$/.test(m))) {
    for (const f of readdirSync(join(root, month))) {
      const m = /^poam-(\d{4}-\d{2}-\d{2})\.csv$/.exec(f);
      if (m && m[1] <= today) files.push([m[1], join(root, month, f)]);
    }
  }
  files.sort();
  return files.length ? parseCsv(readFileSync(files[files.length - 1][1], 'utf8')) : [];
}

export function carryForward(items, previous, today, ran = null, cfg = settings()) {
  const prior = (p) => ({ source: p['Weakness Detector Source'], controls: p.Controls, name: p['Weakness Name'], asset: p['Asset Identifier'] });
  const before = new Map(previous.filter((p) => p.Status !== 'Closed').map((p) => [keyOf(prior(p)), p]));
  const idPattern = new RegExp(`^${cfg.idPrefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}-(\\d+)$`);
  let next = Math.max(0, ...previous.map((p) => Number(idPattern.exec(p['POA&M ID'])?.[1] || 0)));
  const seen = new Set();
  const out = items.map((it) => {
    const old = before.get(keyOf(it));
    if (old) { seen.add(keyOf(it)); return { ...it, id: old['POA&M ID'], detected: old['Original Detection Date'], status: 'Open', statusDate: today }; }
    next += 1;
    return { ...it, id: `${cfg.idPrefix}-${String(next).padStart(4, '0')}`, status: 'Open', statusDate: today };
  });
  const row = (p, status, statusDate) => ({ id: p['POA&M ID'], controls: p.Controls, name: p['Weakness Name'], description: p['Weakness Description'],
    source: p['Weakness Detector Source'], sourceId: p['Weakness Source Identifier'], asset: p['Asset Identifier'], detected: p['Original Detection Date'],
    risk: p['Original Risk Rating'], plan: p['Overall Remediation Plan'], boundary: p.Boundary, status, statusDate });
  for (const [key, p] of before) {
    if (seen.has(key)) continue;
    // Closed only when its detector ran again and no longer finds it; otherwise it stays open as last reported.
    const rescanned = !ran || ran.has(p['Weakness Detector Source']);
    out.push(row(p, rescanned ? 'Closed' : 'Open', rescanned ? today : p['Status Date'] || today));
  }
  // Items closed earlier this month stay on this month's POA&M as Closed.
  for (const p of previous) if (p.Status === 'Closed' && String(p['Status Date']).slice(0, 7) === today.slice(0, 7)) out.push(row(p, 'Closed', p['Status Date']));
  return out;
}

export function buildPoam({ dir, gapFile = null, today = localDay(), inventory = null, config = {} }) {
  const cfg = settings(config);
  const items = [], ran = new Set();
  if (gapFile && existsSync(gapFile)) { ran.add('Gap assessment'); items.push(...gapItems(readFileSync(gapFile, 'utf8'), today, cfg)); }
  const scans = scanItems(dir, today, cfg);
  items.push(...scans.items);
  scans.ran.forEach((s) => ran.add(s));
  if (inventory) { ran.add('Scan coverage'); items.push(...coverageItems(coverage(dir, inventory), today, cfg)); }
  return carryForward(items, previousPoam(dir, today), today, ran, cfg).map((it) => ({ ...it, due: addDays(it.detected, cfg.deadlines[it.risk] ?? cfg.deadlines.Moderate) }));
}

export function toCsv(items, config = {}) {
  const cfg = settings(config);
  const cell = (v) => `"${String(v ?? '').replaceAll('"', '""')}"`;
  const rows = items.map((it) => [it.id, it.controls, it.name, it.description, it.source, it.sourceId, it.asset, cfg.pointOfContact, it.detected, it.risk, it.due, it.plan, it.status, it.statusDate, it.boundary]);
  return [COLUMNS, ...rows].map((r) => r.map(cell).join(',')).join('\n') + '\n';
}
