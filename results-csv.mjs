// Raw scan results as one CSV, since assessors want raw scan files in CSV or Excel: every Trivy vulnerability, secret and
// misconfiguration, every nuclei finding and every Dependabot alert in one month's scan folder (testssl.sh and the check
// files write their own CSV).
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export function resultsCsv(dir) {
  const files = readdirSync(dir).sort();
  const read = (f) => readFileSync(join(dir, f), 'utf8');
  const cell = (v) => `"${String(v ?? '').replaceAll('"', '""')}"`;
  const rows = [['scanner', 'component', 'target', 'type', 'id', 'package', 'installed', 'fixed', 'severity', 'title']];
  for (const f of files.filter((x) => /^trivy-.+-\d{4}-\d{2}-\d{2}\.json$/.test(x))) {
    const component = f.replace(/^trivy-|-\d{4}-\d{2}-\d{2}\.json$/g, '');
    for (const r of JSON.parse(read(f)).Results || []) {
      for (const v of r.Vulnerabilities || []) rows.push(['trivy', component, r.Target, 'vulnerability', v.VulnerabilityID, v.PkgName, v.InstalledVersion, v.FixedVersion, v.Severity, v.Title]);
      for (const s of r.Secrets || []) rows.push(['trivy', component, `${r.Target}:${s.StartLine}`, 'secret', s.RuleID, '', '', '', s.Severity, s.Title]);
      for (const m of r.Misconfigurations || []) rows.push(['trivy', component, r.Target, 'misconfiguration', m.ID, '', '', '', m.Severity, m.Title]);
    }
  }
  for (const f of files.filter((x) => /^nuclei-\d{4}-\d{2}-\d{2}\.jsonl$/.test(x))) {
    for (const line of read(f).split('\n').filter((l) => l.trim())) {
      const n = JSON.parse(line);
      rows.push(['nuclei', 'web', n['matched-at'] || n.host, n.type, n['template-id'], '', '', '', n.info?.severity, n.info?.name]);
    }
  }
  for (const f of files.filter((x) => /^dependabot-\d{4}-\d{2}-\d{2}\.json$/.test(x))) {
    for (const a of JSON.parse(read(f)).flat()) {
      rows.push(['dependabot', a.dependency?.manifest_path, a.html_url, 'vulnerability', a.security_advisory?.ghsa_id, a.dependency?.package?.name,
        a.security_vulnerability?.vulnerable_version_range, a.security_vulnerability?.first_patched_version?.identifier, a.security_advisory?.severity, a.security_advisory?.summary]);
    }
  }
  return rows.map((r) => r.map(cell).join(',')).join('\n') + '\n';
}
