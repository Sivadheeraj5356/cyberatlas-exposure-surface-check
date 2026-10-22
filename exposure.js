// Exposure-surface QA for internet-mapping results: reviews discovered services for
// the exposure patterns security teams actually chase - databases on public ports,
// admin panels, login pages on odd subdomains, expired or self-signed TLS, and dev
// environments indexed in production scans. Heuristic review of pasted scan lines.
// Pure functions, no DOM.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ExposureSurfaceCheck = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  const DB_PORTS = new Set(['3306', '5432', '27017', '6379', '9200', '5984', '1433']);
  function parseScans(input) {
    const rows = [];
    const skipped = [];
    input.split('\n').forEach((raw, i) => {
      const line = raw.trim();
      if (!line) return;
      const p = raw.split('|').map((s) => s.trim());
      if (p.length >= 3 && p[0]) rows.push({ host: p[0], port: p[1], text: p.slice(2).join(' | '), line: i + 1 });
      else skipped.push(i + 1);
    });
    return { rows, skipped };
  }
  function check(input) {
    const { rows, skipped } = typeof input === 'string' ? parseScans(input) : input;
    const findings = [];
    const push = (level, code, text) => findings.push({ level, code, text });

    rows.forEach((r) => {
      if (DB_PORTS.has(r.port))
        push('error', 'DATABASE_PORT_PUBLIC', `Line ${r.line}: ${r.host}:${r.port} looks like a database port reachable in the scan ("${r.text.slice(0, 50)}") - verify it is intentionally public; it usually should not be.`);
      if (/(admin|phpmyadmin|grafana|kibana|jenkins|console|dashboard)/i.test(r.text) && !/login|auth/i.test(r.text))
        push('warn', 'ADMIN_PANEL_NO_AUTH_HINT', `Line ${r.line}: ${r.host} serves what looks like an admin panel ("${r.text.slice(0, 50)}") with no auth hint in the banner - verify access control.`);
      if (/^(dev|staging|test|uat|beta)\./i.test(r.host))
        push('warn', 'DEV_HOST_PUBLIC', `Line ${r.line}: ${r.host} looks like a non-production environment visible in the scan - verify it carries no production data or credentials.`);
      if (/expired|self-signed|invalid cert/i.test(r.text))
        push('warn', 'TLS_ISSUE', `Line ${r.line}: ${r.host}:${r.port} has a TLS concern ("${r.text.slice(0, 50)}") - expired or self-signed certs erode trust and may indicate unmaintained infrastructure.`);
      if (/telnet|^23$/.test(r.port) || /ftp anonymous/i.test(r.text))
        push('error', 'LEGACY_PLAINTEXT_SERVICE', `Line ${r.line}: ${r.host}:${r.port} appears to run a legacy plaintext service - telnet/ftp-anonymous style exposure is rarely intentional.`);
    });

    const hosts = new Set(rows.map((r) => r.host));
    if (skipped.length) push('warn', 'UNPARSED', `Line(s) ${skipped.join(', ')} skipped - expected host | port | banner.`);
    if (!findings.length && rows.length)
      push('ok', 'SURFACE_CLEAN', `No exposure patterns detected across ${hosts.size} host(s) by these heuristics - a banner-level screen, not a vulnerability scan; see Limitations.`);
    return { findings, stats: { rows: rows.length, hosts: hosts.size } };
  }
  return { parseScans, check };
});
