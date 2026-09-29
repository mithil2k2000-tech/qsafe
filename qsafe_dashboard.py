"""
QSafe dashboard: turns scan findings into ONE self-contained HTML file
(no internet, no external scripts) that you can open in any browser or email.

Everything from the scanned files is inserted with textContent, never as HTML,
so a malicious string inside a scanned file cannot run code in the dashboard.
"""
import json

TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QSafe Quantum-Readiness Dashboard</title>
<style>
:root{
  color-scheme: light;
  --page:#f4f4f2; --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e; --ink3:#6b6a66;
  --line:#dddcd7; --grid:#e8e7e3; --series:#2a78d6; --hover:#f0efec;
  --critical:#d03b3b; --serious:#ec835a; --warning:#fab219; --good:#0ca30c;
}
@media (prefers-color-scheme: dark){
  :root:where(:not([data-theme="light"])){
    color-scheme: dark;
    --page:#121211; --surface:#1a1a19; --ink:#ffffff; --ink2:#c3c2b7; --ink3:#9a998f;
    --line:#33332f; --grid:#2c2c2a; --series:#3987e5; --hover:#262624;
  }
}
:root[data-theme="dark"]{
  color-scheme: dark;
  --page:#121211; --surface:#1a1a19; --ink:#ffffff; --ink2:#c3c2b7; --ink3:#9a998f;
  --line:#33332f; --grid:#2c2c2a; --series:#3987e5; --hover:#262624;
}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-start;justify-content:space-between;margin-bottom:20px}
h1{font-size:22px;margin:0 0 4px;font-weight:650}
.sub{color:var(--ink2);font-size:13px;overflow-wrap:anywhere}
button{font:inherit;color:inherit;cursor:pointer}
.theme{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:6px 12px;font-size:13px;color:var(--ink2)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px}
.grid{display:grid;gap:12px}
.kpis{grid-template-columns:repeat(5,minmax(0,1fr));margin-bottom:12px}
@media (max-width:820px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.kpis .score{grid-column:1/-1}}
.score .big{font-size:44px;font-weight:700;line-height:1.05;font-variant-numeric:tabular-nums}
.score .big small{font-size:16px;font-weight:500;color:var(--ink2)}
.meter{height:8px;border-radius:4px;background:var(--grid);margin:10px 0 8px;overflow:hidden}
.meter i{display:block;height:100%;border-radius:4px}
.verdict{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--ink2)}
.tile{text-align:left;display:flex;flex-direction:column;gap:2px;border:1px solid var(--line);background:var(--surface);border-radius:12px;padding:14px 16px}
.filtered .tile[aria-pressed="true"]{outline:2px solid var(--series);outline-offset:-1px}
.tile .n{font-size:30px;font-weight:700;font-variant-numeric:tabular-nums;line-height:1.1}
.tile .l{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--ink2)}
.tile .d{font-size:12px;color:var(--ink3)}
.mk{display:inline-block;width:12px;height:12px;flex:none;background:currentColor}
.mk.critical{background:var(--critical);border-radius:50%}
.mk.high{background:var(--serious);clip-path:polygon(50% 0,100% 100%,0 100%)}
.mk.medium{background:var(--warning);clip-path:polygon(50% 0,100% 50%,50% 100%,0 50%)}
.mk.good{background:var(--good);border-radius:3px}
.charts{grid-template-columns:1fr 1fr;margin-bottom:12px}
@media (max-width:820px){.charts{grid-template-columns:1fr}}
h2{font-size:15px;margin:0 0 2px;font-weight:650}
.hint{font-size:12px;color:var(--ink3);margin:0 0 12px}
.bar{display:grid;grid-template-columns:minmax(90px,38%) 1fr;align-items:center;gap:10px;padding:5px 0;border-top:1px solid var(--grid)}
.bar:first-of-type{border-top:0}
.bar .lab{font-size:13px;color:var(--ink2);overflow-wrap:anywhere}
.bar .trk{display:flex;align-items:center;gap:8px;min-width:0}
.bar .fill{height:12px;background:var(--series);border-radius:0 4px 4px 0;min-width:2px}
.bar .val{font-size:12px;color:var(--ink);font-variant-numeric:tabular-nums}
.bar:hover{background:var(--hover)}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px}
.tools input{flex:1 1 220px;background:var(--page);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font:inherit;font-size:13px}
.tools .count{font-size:12px;color:var(--ink3)}
.link{background:none;border:0;color:var(--series);padding:4px 6px;font-size:13px;text-decoration:underline}
.tw{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th{text-align:left;font-weight:600;color:var(--ink2);border-bottom:1px solid var(--line);padding:8px 8px;white-space:nowrap}
td{padding:8px;border-bottom:1px solid var(--grid);vertical-align:top}
td.loc,td.det{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;overflow-wrap:anywhere}
td.det{color:var(--ink2)}
tr.row:hover td{background:var(--hover)}
tr.adv td{background:var(--hover);color:var(--ink2)}
.rk{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.fbtn{background:none;border:0;padding:0;text-align:left;font-weight:550}
.fbtn:focus-visible,.tile:focus-visible,.theme:focus-visible,.link:focus-visible{outline:2px solid var(--series);outline-offset:2px}
.order{margin:0;padding-left:20px;color:var(--ink2);font-size:13px}
.order li{margin:4px 0}
#tip{position:fixed;z-index:9;pointer-events:none;background:var(--ink);color:var(--surface);font-size:12px;padding:6px 8px;border-radius:6px;max-width:280px;display:none;overflow-wrap:anywhere}
.empty{color:var(--ink3);font-size:13px;padding:16px 0}
@media (max-width:640px){
  thead{display:none}
  table,tbody{display:block}
  tr.row{display:block;border-bottom:1px solid var(--grid);padding:10px 0}
  tr.row td{display:block;border:0;padding:1px 0}
  tr.row td.loc{color:var(--ink2)}
  tr.adv{display:block}
  tr.adv td{display:block;padding:8px;border:0;border-radius:6px}
  .tw{overflow-x:visible}
}
footer{margin-top:20px;font-size:12px;color:var(--ink3)}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>Quantum-readiness dashboard</h1>
      <div class="sub" id="meta"></div>
    </div>
    <button class="theme" id="theme" type="button">Switch theme</button>
  </header>

  <section class="grid kpis" aria-label="Summary">
    <div class="card score">
      <div class="l" style="font-size:13px;color:var(--ink2)">Quantum-readiness score</div>
      <div class="big"><span id="scoreN"></span><small> / 100</small></div>
      <div class="meter" role="img" aria-label="score meter"><i id="scoreBar"></i></div>
      <div class="verdict"><span class="mk" id="scoreMk"></span><span id="scoreTxt"></span></div>
    </div>
    <button class="tile" id="t-CRITICAL" type="button" aria-pressed="true"><span class="n"></span><span class="l"><span class="mk critical"></span>Critical</span><span class="d">Keys and certificates a quantum computer can break</span></button>
    <button class="tile" id="t-HIGH" type="button" aria-pressed="true"><span class="n"></span><span class="l"><span class="mk high"></span>High</span><span class="d">Code or config using RSA, ECC, DH</span></button>
    <button class="tile" id="t-MEDIUM" type="button" aria-pressed="true"><span class="n"></span><span class="l"><span class="mk medium"></span>Medium</span><span class="d">Weak or weakened crypto</span></button>
    <button class="tile" id="t-GOOD" type="button" aria-pressed="true"><span class="n"></span><span class="l"><span class="mk good"></span>Good</span><span class="d">Post-quantum already in use</span></button>
  </section>

  <section class="grid charts">
    <div class="card"><h2>Vulnerable findings by type</h2><p class="hint">Critical + High only. Hover a bar for detail.</p><div id="chartType"></div></div>
    <div class="card"><h2>Where to start: most-exposed files</h2><p class="hint">Critical + High findings per file or server.</p><div id="chartFile"></div></div>
  </section>

  <section class="card" style="margin-bottom:12px">
    <h2>Migration order</h2>
    <p class="hint">Do these in sequence.</p>
    <ol class="order">
      <li><b>Key exchange and long-lived secrets</b> (TLS, VPN, file and database encryption): exposed to "harvest now, decrypt later" today. Move to hybrid ML-KEM.</li>
      <li><b>Long-lived signatures</b> (root CAs, firmware and code signing): plan ML-DSA / SLH-DSA.</li>
      <li><b>Short-lived signatures and auth</b> (JWT, SSH user keys) once libraries support PQC.</li>
      <li><b>Clean-up:</b> remove MD5, SHA-1, 3DES, RC4; use AES-256 and SHA-384+.</li>
      <li><b>Crypto-agility:</b> centralise crypto config so algorithms can be swapped without rewrites.</li>
    </ol>
  </section>

  <section class="card">
    <h2>All findings</h2>
    <p class="hint">Click a finding for the recommended fix. The tiles above filter this table.</p>
    <div class="tools">
      <input id="q" type="search" placeholder="Search finding, file or detail" aria-label="Search findings">
      <button class="link" id="reset" type="button">Show all risks</button>
      <span class="count" id="count"></span>
    </div>
    <div class="tw"><table>
      <thead><tr><th>Risk</th><th>Finding</th><th>Location</th><th>Detail</th></tr></thead>
      <tbody id="rows"></tbody>
    </table></div>
    <div class="empty" id="empty" hidden>No findings match.</div>
  </section>
  <footer>Generated by QSafe. Scan results only cover files the scanner could read; treat this as a starting inventory, not a full audit.</footer>
</div>
<div id="tip" role="tooltip"></div>
<script type="application/json" id="data">__DATA__</script>
<script>
(function(){
const D = JSON.parse(document.getElementById('data').textContent);
const RISKS = ['CRITICAL','HIGH','MEDIUM','GOOD'];
const MK = {CRITICAL:'critical',HIGH:'high',MEDIUM:'medium',GOOD:'good'};
const LABEL = {CRITICAL:'Critical',HIGH:'High',MEDIUM:'Medium',GOOD:'Good'};
const CAT = {'key-material':'Keys and key files','certificate':'Certificates','code':'Code (RSA / ECC / DH)','ssh':'SSH keys','tls':'TLS settings','hash':'Weak hashes','symmetric':'Weak symmetric ciphers'};
const $ = id => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const assets = D.assets || [];
const active = new Set(RISKS);
let query = '';

$('meta').textContent = 'Target: ' + D.target + '  ·  ' + D.files_scanned + ' files scanned  ·  ' + D.generated;

// score
const s = D.quantum_readiness_score;
$('scoreN').textContent = s;
const band = s >= 80 ? ['good','Mostly quantum-ready'] : s >= 50 ? ['medium','Fair: plan your migration'] : ['critical','Poor: act now'];
$('scoreTxt').textContent = band[1];
$('scoreMk').className = 'mk ' + band[0];
const bar = $('scoreBar'); bar.style.width = s + '%';
bar.style.background = 'var(--' + (band[0] === 'medium' ? 'warning' : band[0]) + ')';

// tiles
RISKS.forEach(r => {
  const t = $('t-' + r);
  t.querySelector('.n').textContent = (D.summary || {})[r] || 0;
  t.addEventListener('click', () => {
    if (active.size === RISKS.length) { active.clear(); active.add(r); }
    else if (active.has(r)) { active.delete(r); if (!active.size) RISKS.forEach(x => active.add(x)); }
    else active.add(r);
    render();
  });
});
$('reset').addEventListener('click', () => { RISKS.forEach(x => active.add(x)); $('q').value = ''; query = ''; render(); });
$('q').addEventListener('input', e => { query = e.target.value.toLowerCase(); renderTable(); });

// tooltip
const tip = $('tip');
document.addEventListener('mousemove', e => {
  const t = e.target.closest && e.target.closest('[data-tip]');
  if (!t) { tip.style.display = 'none'; return; }
  tip.textContent = t.getAttribute('data-tip');
  tip.style.display = 'block';
  const w = tip.offsetWidth, h = tip.offsetHeight;
  tip.style.left = Math.min(e.clientX + 14, innerWidth - w - 8) + 'px';
  tip.style.top = Math.max(8, e.clientY - h - 10) + 'px';
});

// bar charts (Critical + High only)
const vuln = assets.filter(a => a.risk === 'CRITICAL' || a.risk === 'HIGH');
function bars(host, rows, tipFn) {
  host.textContent = '';
  if (!rows.length) { host.appendChild(el('div', 'empty', 'Nothing vulnerable found here.')); return; }
  const max = Math.max.apply(null, rows.map(r => r[1]));
  rows.forEach(r => {
    const row = el('div', 'bar'); row.setAttribute('data-tip', tipFn(r));
    row.appendChild(el('div', 'lab', r[0]));
    const trk = el('div', 'trk'); const f = el('div', 'fill'); f.style.width = Math.max(2, r[1] / max * 78) + '%';
    trk.appendChild(f); trk.appendChild(el('span', 'val', r[1])); row.appendChild(trk); host.appendChild(row);
  });
}
const byType = {}; vuln.forEach(a => { const k = CAT[a.category] || a.category; byType[k] = (byType[k] || 0) + 1; });
bars($('chartType'), Object.entries(byType).sort((a, b) => b[1] - a[1]), r => r[0] + ': ' + r[1] + ' critical/high finding(s)');
const byFile = {}; vuln.forEach(a => { const k = String(a.location).replace(/:\d+$/, ''); byFile[k] = (byFile[k] || 0) + 1; });
bars($('chartFile'), Object.entries(byFile).sort((a, b) => b[1] - a[1]).slice(0, 8), r => r[0] + ': ' + r[1] + ' critical/high finding(s)');

// table
const open = new Set();
function renderTable() {
  const body = $('rows'); body.textContent = '';
  const list = assets.filter(a => active.has(a.risk) && (!query || (a.finding + ' ' + a.location + ' ' + a.detail).toLowerCase().includes(query)));
  const LIMIT = 500;
  list.slice(0, LIMIT).forEach((a, i) => {
    const tr = el('tr', 'row');
    const c1 = el('td'); const rk = el('span', 'rk'); rk.appendChild(el('span', 'mk ' + MK[a.risk])); rk.appendChild(document.createTextNode(LABEL[a.risk])); c1.appendChild(rk);
    const c2 = el('td'); const b = el('button', 'fbtn', a.finding); b.type = 'button'; b.setAttribute('aria-expanded', open.has(i) ? 'true' : 'false'); c2.appendChild(b);
    tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(el('td', 'loc', a.location)); tr.appendChild(el('td', 'det', a.detail));
    body.appendChild(tr);
    let adv = null;
    const toggle = () => {
      if (adv) { adv.remove(); adv = null; b.setAttribute('aria-expanded', 'false'); return; }
      adv = el('tr', 'adv'); const td = el('td'); td.colSpan = 4; td.textContent = 'Fix: ' + (a.advice || 'Review manually.'); adv.appendChild(td);
      tr.after(adv); b.setAttribute('aria-expanded', 'true');
    };
    tr.addEventListener('click', toggle);
    b.addEventListener('click', e => e.stopPropagation() || toggle());
  });
  $('count').textContent = list.length + ' of ' + assets.length + ' findings' + (list.length > LIMIT ? ' (showing first ' + LIMIT + ')' : '');
  $('empty').hidden = list.length > 0;
}
function render() {
  document.body.classList.toggle('filtered', active.size !== RISKS.length);
  RISKS.forEach(r => $('t-' + r).setAttribute('aria-pressed', active.has(r) ? 'true' : 'false'));
  renderTable();
}
render();

// theme toggle
$('theme').addEventListener('click', () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  root.dataset.theme = dark ? 'light' : 'dark';
});
})();
</script>
</body>
</html>
"""


def write_dashboard(findings, target, files, out_prefix, counts, score, generated):
    data = {"tool": "QSafe scanner", "generated": generated, "target": target,
            "files_scanned": files, "summary": counts, "quantum_readiness_score": score,
            "assets": findings}
    blob = json.dumps(data).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    path = out_prefix + ".html"
    with open(path, "w", encoding="utf-8") as f:
        f.write(TEMPLATE.replace("__DATA__", blob))
    return path
