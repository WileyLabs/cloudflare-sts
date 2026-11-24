// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

// Single-file dashboard: no dependencies, no external requests (the CSP only allows this page and same-origin fetches).
// Everything dynamic is rendered with textContent, never innerHTML.
export const PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>cf-sts</title>
<style>
  :root{--bg:#f6f7f9;--card:#fff;--fg:#14171f;--muted:#68717f;--line:#e4e7ec;--accent:#f6821f;--ok:#0f7b3f;--ok-bg:#dcf5e5;--warn:#9a5b00;--warn-bg:#fdecc8;--bad:#b3261e;--bad-bg:#fde3e1;--idle:#59616e;--idle-bg:#eceef2;--chip:#eef1f6;--shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.08)}
  :root[data-theme=dark]{--bg:#0e1116;--card:#171b22;--fg:#e8ebf0;--muted:#8d97a6;--line:#262c36;--ok:#5fd592;--ok-bg:#12301f;--warn:#f0b955;--warn-bg:#352708;--bad:#ff8a80;--bad-bg:#3a1512;--idle:#a3acb9;--idle-bg:#222832;--chip:#222832;--shadow:none}
  @media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0e1116;--card:#171b22;--fg:#e8ebf0;--muted:#8d97a6;--line:#262c36;--ok:#5fd592;--ok-bg:#12301f;--warn:#f0b955;--warn-bg:#352708;--bad:#ff8a80;--bad-bg:#3a1512;--idle:#a3acb9;--idle-bg:#222832;--chip:#222832;--shadow:none}}
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
  main{max-width:1280px;margin:0 auto;padding:20px 16px 48px}
  header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px}
  header h1{font-size:18px;margin:0} header .sub{color:var(--muted);font-size:13px} .grow{flex:1}
  .logo{width:32px;height:32px;border-radius:9px;background:var(--accent);display:grid;place-items:center;color:#fff}
  button,select,input{font:inherit;color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:6px 10px}
  button{cursor:pointer} button:hover{border-color:var(--muted)} button.on{background:var(--accent);border-color:var(--accent);color:#fff}
  input[type=search]{min-width:220px}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:12px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;box-shadow:var(--shadow)}
  .card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em} .card .v{font-size:28px;font-weight:650;margin-top:2px}
  .chart{grid-column:span 2;min-width:260px} .bars{display:flex;align-items:flex-end;gap:3px;height:54px;margin-top:8px}
  .bars i{flex:1;background:var(--accent);opacity:.85;border-radius:2px 2px 0 0;min-height:2px} .bars i.z{background:var(--line);opacity:1}
  nav.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin:16px 0 12px}
  nav.tabs button{border:0;border-bottom:2px solid transparent;border-radius:0;background:none;padding:8px 14px;color:var(--muted)}
  nav.tabs button.on{color:var(--fg);border-bottom-color:var(--accent);background:none}
  .bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center} .count{color:var(--muted);font-size:13px}
  .tablewrap{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:auto;box-shadow:var(--shadow)}
  table{border-collapse:collapse;width:100%} th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
  th{font-size:12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em;background:var(--card);position:sticky;top:0}
  tr.row{cursor:pointer} tr.row:hover td{background:color-mix(in srgb,var(--accent) 5%,transparent)} tr:last-child td{border-bottom:0}
  tr.detail td{background:var(--bg);font-size:13px} tr.detail table th{position:static;background:none} .kv{display:grid;grid-template-columns:120px 1fr;gap:4px 12px} .kv b{color:var(--muted);font-weight:500}
  code,.mono{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
  .pill{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:600}
  .active{background:var(--ok-bg);color:var(--ok)} .expired{background:var(--idle-bg);color:var(--idle)} .revoked{background:var(--warn-bg);color:var(--warn)} .denied{background:var(--bad-bg);color:var(--bad)}
  .chip{display:inline-block;background:var(--chip);border-radius:6px;padding:1px 7px;margin:1px 3px 1px 0;font-size:12px} .scope{color:var(--muted);font-size:12px;margin:2px 0}
  .muted{color:var(--muted)} .empty{padding:40px;text-align:center;color:var(--muted)} .copy{border:0;background:none;padding:0 4px;color:var(--muted)}
  .rules{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:12px} .rules h3{margin:0 0 2px;font-size:15px} .rules .claim{margin:2px 0}
  .tag{display:inline-block;border-radius:6px;padding:1px 8px;font-size:12px;font-weight:600;background:color-mix(in srgb,var(--c,#68717f) 16%,transparent);color:var(--c,var(--muted));white-space:nowrap}
  .t-github{--c:#8250df} .t-aws{--c:#e07b00} .t-gcp{--c:#1a73e8} .t-spiffe{--c:#0f9d8a}
  .k-branch{--c:#1a73e8} .k-tag{--c:#c2185b} .k-environment{--c:#0f7b3f} .k-pull_request{--c:#8250df} .k-user{--c:#e07b00} .k-role{--c:#b3261e} .k-workload{--c:#0f9d8a} .k-id{--c:#68717f} .k-other{--c:#68717f}
  :root[data-theme=dark] .tag{filter:brightness(1.35)}
  .fwrap{position:relative} .menu{position:absolute;z-index:5;top:100%;right:0;margin-top:4px;width:260px;background:var(--card);border:1px solid var(--line);border-radius:10px;box-shadow:0 6px 20px rgba(0,0,0,.18);padding:12px}
  .menu select{width:100%} .fl{display:block;color:var(--muted);font-size:12px;margin:8px 0 3px} .fl:first-child{margin-top:0}
  .active{display:flex;gap:6px 10px;flex-wrap:wrap;align-items:center;margin:-2px 0 10px;font-size:12px;min-height:18px} #alist{display:contents}
  .af{color:var(--muted)} .af b{color:var(--fg);font-weight:600} .af button{border:0;background:none;padding:0 3px;color:var(--muted);font-size:14px;line-height:1}
  button.link{border:0;background:none;padding:0;color:var(--accent);font-size:12px}
  .more{border:0;background:none;padding:0 4px;color:var(--accent);font-size:12px;cursor:pointer}
  .err{color:var(--bad);margin:8px 0}
  @media (max-width:640px){.chart{grid-column:auto} input[type=search]{min-width:0;flex:1}}
</style></head><body><main>
<header>
  <div class="logo"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3m-3 3 3 3m-5-1 2 2"/></svg></div>
  <div><h1>cf-sts</h1><div class="sub">Short-lived Cloudflare tokens for OIDC callers. Token values are never stored.</div></div>
  <div class="grow"></div>
  <span class="count" id="updated"></span>
  <button id="auto" class="on" title="Refresh every 30 seconds">Auto-refresh</button>
  <button id="refresh">Refresh</button>
  <button id="theme" title="Toggle theme">Theme</button>
</header>
<div class="err" id="error" hidden></div>
<section class="cards">
  <div class="card"><div class="k">Active tokens</div><div class="v" id="s-active">-</div></div>
  <div class="card"><div class="k">Minted (24h)</div><div class="v" id="s-minted">-</div></div>
  <div class="card"><div class="k">Revoked (24h)</div><div class="v" id="s-revoked">-</div></div>
  <div class="card"><div class="k">Denied (24h)</div><div class="v" id="s-denied">-</div></div>
  <div class="card chart"><div class="k">Mints per hour, last 24h</div><div class="bars" id="bars"></div></div>
</section>
<nav class="tabs"><button data-tab="mints" class="on">Mints</button><button data-tab="policy">Policy</button><button data-tab="denied">Denied</button><button data-tab="cleanup">Cleanup</button></nav>

<section id="tab-mints">
  <div class="bar">
    <input type="search" id="q" placeholder="Search subject, repo, rule, token id">
    <span class="grow"></span>
    <span class="fwrap"><button id="addf" title="Add a filter">Filter</button>
      <div class="menu" id="fmenu" hidden>
        <label class="fl">Filter by</label><select id="fsel"></select>
        <label class="fl">Value</label><select id="fval"></select>
        <button id="fadd" class="on" style="margin-top:8px;width:100%">Add filter</button>
        <label class="fl" style="margin-top:12px">Sort</label>
        <select id="sort"><option value="new">Newest first</option><option value="old">Oldest first</option><option value="exp">Expiring soonest</option></select>
      </div></span>
  </div>
  <div class="active" id="active"><span id="alist"></span><button id="reset" class="link" hidden>Clear all</button><span class="count" id="count"></span></div>
  <div id="fpool" hidden>
    <select id="status"><option value="">All statuses</option><option>active</option><option>expired</option><option>revoked</option></select>
    <select id="rule"><option value="">All rules</option></select>
    <select id="provider"><option value="">All providers</option></select>
    <select id="repo"><option value="">All repos / identities</option></select>
    <select id="subject"><option value="">All subjects</option></select>
    <select id="perm"><option value="">All permissions</option></select>
    <select id="range"><option value="">Any time</option><option value="3600">Last hour</option><option value="86400">Last 24h</option><option value="604800">Last 7 days</option><option value="2592000">Last 30 days</option></select>
  </div>
  <div class="tablewrap"><table><thead><tr><th>Status</th><th>Remaining</th><th>Last issued</th><th>Provider</th><th>Repo / identity</th><th>Subject</th><th>Rule</th><th>Permissions</th><th>Mints</th></tr></thead><tbody id="rows"></tbody></table><div class="empty" id="mints-empty" hidden>No tokens match.</div></div>
</section>
<section id="tab-policy" hidden><div class="rules" id="rules"></div><div id="profiles"></div></section>
<section id="tab-cleanup" hidden>
  <div class="cards">
    <div class="card"><div class="k">Next cleanup in</div><div class="v" id="cl-timer">-</div><div class="muted" id="cl-at"></div></div>
    <div class="card"><div class="k">Deleted next run</div><div class="v" id="cl-now">-</div><div class="muted">expired, past grace</div></div>
    <div class="card"><div class="k">In grace period</div><div class="v" id="cl-soon">-</div><div class="muted">deleted at a later run</div></div>
    <div class="card"><div class="k" id="cl-mk">Minted</div><div class="v" id="cl-mt">-</div></div>
    <div class="card"><div class="k" id="cl-dk">Deleted by cleanup</div><div class="v" id="cl-dt">-</div></div>
  </div>
  <div class="card" style="margin-bottom:10px"><div id="cl-info" class="muted"></div></div>
  <div class="card" style="margin-bottom:12px">
    <div class="bar" style="margin-bottom:4px"><div class="k" style="flex:1">Minted vs deleted by cleanup (counters only)</div>
      <select id="cl-range"><option value="1">Last 24h (hourly)</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option></select></div>
    <div class="bars" id="cl-bars" style="height:90px"></div>
    <div class="count"><i style="display:inline-block;width:10px;height:10px;background:var(--accent);opacity:.85"></i> minted &nbsp; <i style="display:inline-block;width:10px;height:10px;background:var(--ok)"></i> deleted</div>
  </div>
  <div class="tablewrap"><table><thead><tr><th>When</th><th>Token id</th><th>Name</th><th>Expired / expires</th></tr></thead><tbody id="cl-rows"></tbody></table><div class="empty" id="cl-empty" hidden>Nothing to delete.</div></div>
</section>
<section id="tab-denied" hidden>
  <div class="tablewrap"><table><thead><tr><th>When</th><th>Reason</th><th>HTTP</th><th>Subject / repo</th><th>IP</th><th>Ray</th></tr></thead><tbody id="denials"></tbody></table><div class="empty" id="denied-empty" hidden>No authenticated denials recorded.</div></div>
</section>
</main>
<script>
var $ = function (id) { return document.getElementById(id); };
var mints = [], expanded = {}, ticking = [], loaded = { policy: false, denied: false, cleanup: false }, timer = null, tab = 'mints';
function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
function now() { return Math.floor(Date.now() / 1000); }
function abs(s) { return new Date(s * 1000).toLocaleString(); }
function ago(s) {
  var d = now() - s;
  if (d < 60) return d + 's ago';
  if (d < 3600) return Math.floor(d / 60) + 'm ago';
  if (d < 86400) return Math.floor(d / 3600) + 'h ago';
  return Math.floor(d / 86400) + 'd ago';
}
function left(s) {
  var d = s - now();
  if (d <= 0) return '-';
  return d >= 3600 ? Math.floor(d / 3600) + 'h ' + Math.floor((d % 3600) / 60) + 'm' : Math.floor(d / 60) + 'm ' + (d % 60) + 's';
}
function statusOf(m) { return m.revoked_at ? 'revoked' : m.expires_at > now() ? 'active' : 'expired'; }
function pill(text, cls) { return el('span', 'pill ' + cls, text); }
function copyBtn(value) {
  var b = el('button', 'copy', 'copy');
  b.onclick = function (ev) { ev.stopPropagation(); if (navigator.clipboard) navigator.clipboard.writeText(value); b.textContent = 'copied'; setTimeout(function () { b.textContent = 'copy'; }, 1200); };
  return b;
}
// A recorded policy item is either a name-based grant ({permissions, zones}) or a raw Cloudflare policy ({permission_groups, resources}).
function describe(p) {
  if (p.permissions) return { perms: p.permissions, scope: p.zones ? 'zones: ' + p.zones.join(', ') : 'whole account' };
  var res = Object.keys(p.resources || {}).map(function (k) { return k.replace('com.cloudflare.api.account.', ''); });
  return { perms: (p.permission_groups || []).map(function (g) { return typeof g === 'string' ? g.slice(0, 8) + '...' : g.id; }), scope: (p.effect || 'allow') + ' ' + res.join(', ') };
}
var PERM_LIMIT = 3;
function permNames(list) {
  var out = [];
  (list || []).forEach(function (p) { describe(p).perms.forEach(function (n) { if (out.indexOf(n) < 0) out.push(n); }); });
  return out;
}
// Shows the first few permissions; a click on "+N more" expands the full list with scopes (and "show less" collapses it).
function perms(list, stopClick) {
  var box = el('div'), all = [];
  (list || []).forEach(function (p) { var d = describe(p); d.perms.forEach(function (n) { all.push(n); }); });
  var open = false;
  function draw() {
    box.replaceChildren();
    if (!open) {
      all.slice(0, PERM_LIMIT).forEach(function (n) { box.append(el('span', 'chip', n)); });
    } else {
      (list || []).forEach(function (p) {
        var d = describe(p);
        d.perms.forEach(function (n) { box.append(el('span', 'chip', n)); });
        box.append(el('div', 'scope', d.scope));
      });
    }
    if (all.length > PERM_LIMIT) {
      var b = el('button', 'more', open ? 'show less' : '+' + (all.length - PERM_LIMIT) + ' more');
      b.onclick = function (ev) { if (stopClick) ev.stopPropagation(); open = !open; draw(); };
      box.append(b);
    }
  }
  draw();
  return box;
}
// Splits a mint into provider / repo-or-identity / subject, for tags and filters.
function parse(m) {
  var iss = m.issuer || '', sub = m.sub || '', provider, repo, kind, value;
  if (iss.indexOf('githubusercontent') >= 0) provider = 'github';
  else if (iss.indexOf('google') >= 0) provider = 'gcp';
  else if (iss.indexOf('amazonaws') >= 0 || iss.indexOf('api.aws') >= 0 || sub.indexOf('arn:') === 0) provider = 'aws';
  else provider = 'spiffe';
  if (provider === 'github') {
    repo = m.repository || (sub.split(':')[1] || sub);
    var rest = sub.split(':').slice(2).join(':');
    if (rest.indexOf('ref:refs/heads/') === 0) { kind = 'branch'; value = rest.slice(15); }
    else if (rest.indexOf('ref:refs/tags/') === 0) { kind = 'tag'; value = rest.slice(14); }
    else if (rest.indexOf('environment:') === 0) { kind = 'environment'; value = rest.slice(12); }
    else if (rest === 'pull_request') { kind = 'pull_request'; value = 'pull request'; }
    else { kind = 'other'; value = rest || sub; }
  } else if (provider === 'aws') {
    var a = sub.split(':'), res = a[5] || sub;
    repo = 'account ' + (a[4] || '?'); kind = res.split('/')[0] === 'role' ? 'role' : 'user'; value = res.split('/').slice(-1)[0];
  } else if (provider === 'gcp') {
    repo = m.repository || sub; kind = 'id'; value = sub;
  } else {
    var path = sub.replace('spiffe://', ''), i = path.indexOf('/');
    repo = i < 0 ? path : path.slice(0, i); kind = 'workload'; value = i < 0 ? '-' : path.slice(i + 1);
  }
  return { provider: provider, repo: repo, kind: kind, value: value };
}
function tag(text, cls, title) { var t = el('span', 'tag ' + cls, text); if (title) t.title = title; return t; }
function who(m) {
  var box = el('div');
  box.append(el('div', 'mono', m.sub));
  var extra = [m.repository, m.actor && '(' + m.actor + ')'].filter(Boolean).join(' ');
  if (extra) box.append(el('div', 'muted', extra));
  return box;
}
function td(tr, child) { var c = tr.insertCell(); if (typeof child === 'string') c.textContent = child; else if (child) c.append(child); return c; }

// Mints with the same subject/repo + rule are grouped into one row (latest mint shown); a click lists every mint in the group.
function renderMints() {
  renderActive();
  var q = $('q').value.trim().toLowerCase(), st = $('status').value, rl = $('rule').value, pv = $('provider').value, rp = $('repo').value, sj = $('subject').value, pm = $('perm').value, rg = Number($('range').value) || 0, so = $('sort').value;
  var rows = $('rows');
  rows.replaceChildren();
  ticking = [];
  var groups = {}, order = [], total = 0;
  mints.forEach(function (m) {
    var status = statusOf(m);
    if (st && st !== status) return;
    if (rl && rl !== m.rule_id) return;
    var pa = parse(m);
    if (pv && pv !== pa.provider) return;
    if (rp && rp !== pa.repo) return;
    if (sj && sj !== pa.kind + ':' + pa.value) return;
    if (rg && m.issued_at < now() - rg) return;
    if (pm && permNames(m.policies).indexOf(pm) < 0) return;
    if (q && [m.sub, m.repository, m.actor, m.rule_id, m.id, m.issuer].join(' ').toLowerCase().indexOf(q) < 0) return;
    total++;
    var key = [m.repository || m.sub, m.rule_id].join('|');
    if (!groups[key]) { groups[key] = { key: key, items: [] }; order.push(groups[key]); }
    groups[key].items.push(m);
  });
  order.forEach(function (g) {
    g.items.sort(function (a, b) { return b.issued_at - a.issued_at; });
    g.last = g.items[0];
    g.active = g.items.filter(function (m) { return statusOf(m) === 'active'; });
  });
  if (so === 'old') order.sort(function (a, b) { return a.last.issued_at - b.last.issued_at; });
  else if (so === 'exp') order.sort(function (a, b) { return (a.active.length ? a.active[a.active.length - 1].expires_at : Infinity) - (b.active.length ? b.active[b.active.length - 1].expires_at : Infinity); });
  else order.sort(function (a, b) { return b.last.issued_at - a.last.issued_at; });

  order.forEach(function (g) {
    var m = g.last, status = statusOf(m), open = !!expanded[g.key];
    var tr = rows.insertRow();
    tr.className = 'row';
    td(tr, pill(status, status));
    var soon = g.active.length ? g.active[g.active.length - 1] : null; // active mint closest to expiry
    var rem = td(tr, soon ? left(soon.expires_at) : '-');
    if (soon) ticking.push([soon, rem]);
    var when = td(tr, ago(m.issued_at)); when.title = abs(m.issued_at);
    var pa = parse(m);
    td(tr, tag(pa.provider, 't-' + pa.provider));
    var rc = td(tr, el('div', 'mono', pa.repo));
    if (m.actor) rc.append(el('div', 'muted', m.actor));
    var subj = td(tr, '');
    subj.append(tag(pa.kind.replace('_', ' '), 'k-' + pa.kind), ' ', el('span', 'mono', pa.value));
    var others = {};
    g.items.forEach(function (x) { if (x.sub !== m.sub) others[x.sub] = 1; });
    var otherList = Object.keys(others);
    if (otherList.length) { var o = el('div', 'muted', '+' + otherList.length + ' other subject' + (otherList.length === 1 ? '' : 's')); o.title = otherList.join(', '); subj.append(o); }
    var rule = td(tr, m.rule_id);
    if (m.description) rule.append(el('div', 'muted', m.description));
    td(tr, perms(m.policies, true));
    var n = td(tr, (open ? '\u25be ' : '\u25b8 ') + g.items.length + (g.items.length === 1 ? ' mint' : ' mints'));
    if (g.active.length) n.append(el('div', 'muted', g.active.length + ' active'));
    tr.onclick = function () { expanded[g.key] = !expanded[g.key]; renderMints(); };
    if (open) {
      var dr = rows.insertRow(); dr.className = 'detail';
      var c = dr.insertCell(); c.colSpan = 9;
      var t = el('table'), h = t.createTHead().insertRow();
      ['Status', 'Remaining', 'Issued', 'Subject', 'Expires', 'Revoked', 'TTL', 'Source IP', 'Ray', 'Token id'].forEach(function (x) { h.append(el('th', '', x)); });
      var body = t.createTBody();
      g.items.forEach(function (x) {
        var s2 = statusOf(x), r = body.insertRow();
        td(r, pill(s2, s2));
        var rc = td(r, s2 === 'active' ? left(x.expires_at) : '-');
        if (s2 === 'active') ticking.push([x, rc]);
        td(r, abs(x.issued_at)); var xp = parse(x), sc = td(r, ''); sc.append(tag(xp.kind.replace('_', ' '), 'k-' + xp.kind), ' ', el('span', 'mono', xp.value)); sc.title = x.sub; td(r, abs(x.expires_at)); td(r, x.revoked_at ? abs(x.revoked_at) : '-');
        td(r, x.ttl + 's'); td(r, x.ip || '-'); td(r, el('code', '', x.ray || '-'));
        var idc = td(r, el('code', '', x.id)); idc.append(copyBtn(x.id));
      });
      c.append(t);
    }
  });
  $('count').textContent = order.length + ' groups (' + total + ' of ' + mints.length + ' mints) shown';
  $('mints-empty').hidden = order.length > 0;
}
function tick() {
  var t = now();
  if (ticking.some(function (x) { return x[0].expires_at <= t; })) return renderMints();
  ticking.forEach(function (x) { x[1].textContent = left(x[0].expires_at); });
}
function renderStats(s) {
  $('s-active').textContent = s.active; $('s-minted').textContent = s.minted_24h; $('s-revoked').textContent = s.revoked_24h; $('s-denied').textContent = s.denied_24h;
  var byHour = {}; s.hourly.forEach(function (h) { byHour[h.hour] = h.n; });
  var top = Math.max.apply(null, [1].concat(s.hourly.map(function (h) { return h.n; })));
  var start = Math.floor(s.now / 3600) * 3600 - 23 * 3600, bars = $('bars');
  bars.replaceChildren();
  for (var i = 0; i < 24; i++) {
    var n = byHour[start + i * 3600] || 0, b = el('i', n ? '' : 'z');
    b.style.height = Math.max(4, Math.round((n / top) * 100)) + '%';
    b.title = new Date((start + i * 3600) * 1000).toLocaleString([], { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' }) + ': ' + n;
    bars.append(b);
  }
}
function renderPolicy(p) {
  var box = $('rules'); box.replaceChildren();
  p.rules.forEach(function (r) {
    var c = el('div', 'card');
    c.append(el('h3', '', r.id));
    if (r.description) c.append(el('div', 'muted', r.description));
    var pl = el('div', 'claim'); pl.append(el('span', 'muted', 'principal: '), el('code', '', [].concat(r.principal).join('  |  '))); c.append(pl);
    Object.keys(r.claims || {}).forEach(function (k) { var v = [].concat(r.claims[k]).join('  |  '); var line = el('div', 'claim'); line.append(el('span', 'muted', k + ': '), el('code', '', v)); c.append(line); });
    c.append(el('div', 'scope', 'max TTL ' + r.max_ttl_seconds + 's' + (r.client_ips ? ' | token pinned to ' + r.client_ips.join(', ') : '')));
    c.append(perms(r.grants));
    if (r.raw_policies) c.append(el('div', 'scope', '+ ' + r.raw_policies + ' raw Cloudflare polic' + (r.raw_policies === 1 ? 'y' : 'ies')));
    box.append(c);
  });
  var pf = $('profiles'); pf.replaceChildren();
  var names = Object.keys(p.profiles || {});
  if (names.length) {
    var c = el('div', 'card'); c.style.marginTop = '12px';
    c.append(el('h3', '', 'Profiles'));
    names.forEach(function (n) { var line = el('div', 'claim'); line.append(el('code', '', n + ': ')); p.profiles[n].permissions.forEach(function (x) { line.append(el('span', 'chip', x)); }); c.append(line); });
    pf.append(c);
  }
}
function renderDenials(list) {
  var rows = $('denials'); rows.replaceChildren();
  list.forEach(function (d) {
    var tr = rows.insertRow();
    var w = td(tr, ago(d.ts)); w.title = abs(d.ts);
    td(tr, pill(d.reason, 'denied')); td(tr, String(d.status));
    td(tr, who({ sub: d.sub, repository: d.repository }));
    td(tr, d.ip || '-'); td(tr, el('code', '', d.ray || '-'));
  });
  $('denied-empty').hidden = list.length > 0;
}
var nextRun = 0;
function clock() {
  if (!nextRun) return;
  var d = nextRun - now();
  $('cl-timer').textContent = d <= 0 ? 'running...' : Math.floor(d / 60) + 'm ' + String(d % 60).padStart(2, '0') + 's';
}
function renderCleanup(d) {
  nextRun = d.next_run;
  $('cl-at').textContent = new Date(d.next_run * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' local | ' + d.schedule;
  $('cl-now').textContent = d.total; $('cl-soon').textContent = d.upcoming_total;
  clock();
  var info = $('cl-info'); info.replaceChildren();
  info.append(el('div', '', 'Deletes only tokens named sts/... that Cloudflare reports as expired at least ' + Math.round(d.grace_seconds / 60) + ' min ago. Active and foreign tokens are never touched. Scanned ' + d.scanned + ' account tokens' + (d.total > d.max_per_run ? ' | max ' + d.max_per_run + ' per run, rest next run' : '') + (d.dry_run ? ' | DRY RUN: nothing is deleted' : '') + '.'));
  var rows = $('cl-rows'); rows.replaceChildren();
  d.tokens.forEach(function (t) { cleanupRow(rows, t, 'next run', 'expired'); });
  d.upcoming.forEach(function (t) { cleanupRow(rows, t, 'at ' + new Date(t.delete_at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), 'revoked'); });
  $('cl-empty').hidden = d.tokens.length + d.upcoming.length > 0;
}
function cleanupRow(rows, t, label, cls) {
  var tr = rows.insertRow();
  td(tr, pill(label, cls)); td(tr, el('code', '', t.id)); td(tr, el('code', '', t.name));
  var sec = Math.floor(Date.parse(t.expires_on) / 1000), w = td(tr, sec <= now() ? ago(sec) : 'in ' + left(sec));
  w.title = t.expires_on;
}
// Paired bars per bucket: minted (accent) and deleted (green), from counters only.
function renderTrend(d) {
  var by = {}, step = d.bucket, start = Math.floor(d.now / step) * step - (d.days === 1 ? 23 : d.days - 1) * step, count = d.days === 1 ? 24 : d.days;
  d.minted.forEach(function (x) { (by[x.t] = by[x.t] || {}).m = x.n; });
  d.deleted.forEach(function (x) { (by[x.t] = by[x.t] || {}).d = x.n; });
  var top = 1, i, k;
  for (k in by) top = Math.max(top, by[k].m || 0, by[k].d || 0);
  var box = $('cl-bars'); box.replaceChildren();
  for (i = 0; i < count; i++) {
    var t = start + i * step, v = by[t] || {}, g = el('div'), a = el('i', v.m ? '' : 'z'), b = el('i', v.d ? '' : 'z');
    g.style.cssText = 'flex:1;display:flex;align-items:flex-end;gap:1px;height:100%';
    a.style.height = Math.max(4, Math.round(((v.m || 0) / top) * 100)) + '%';
    b.style.height = Math.max(4, Math.round(((v.d || 0) / top) * 100)) + '%'; if (v.d) b.style.background = 'var(--ok)';
    g.title = new Date(t * 1000).toLocaleString([], d.days === 1 ? { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' } : { month: 'short', day: 'numeric' }) + ': ' + (v.m || 0) + ' minted, ' + (v.d || 0) + ' deleted';
    g.append(a, b); box.append(g);
  }
  var label = d.days === 1 ? '24h' : d.days + 'd';
  $('cl-mk').textContent = 'Minted (' + label + ')'; $('cl-dk').textContent = 'Deleted by cleanup (' + label + ')';
  $('cl-mt').textContent = d.minted_total; $('cl-dt').textContent = d.deleted_total;
}
function fillSelect(id, label, values) {
  var sel = $(id), cur = sel.value;
  sel.replaceChildren(el('option', '', label)); sel.firstChild.value = '';
  values.sort().forEach(function (r) { var o = el('option', '', r); o.value = r; sel.append(o); });
  sel.value = cur;
}
// provider -> repo -> subject: each select only lists what exists under the selection above it.
function fillRules() {
  var rules = {}, ps = {}, provs = {}, repos = {}, subs = {};
  var pv = $('provider').value, rp = $('repo').value;
  mints.forEach(function (m) {
    var pa = parse(m);
    rules[m.rule_id] = 1; provs[pa.provider] = 1; permNames(m.policies).forEach(function (n) { ps[n] = 1; });
    if (!pv || pv === pa.provider) { repos[pa.repo] = 1; if (!rp || rp === pa.repo) subs[pa.kind + ':' + pa.value] = 1; }
  });
  fillSelect('rule', 'All rules', Object.keys(rules));
  fillSelect('perm', 'All permissions', Object.keys(ps));
  fillSelect('provider', 'All providers', Object.keys(provs));
  fillSelect('repo', 'All repos / identities', Object.keys(repos));
  fillSelect('subject', 'All subjects', Object.keys(subs));
}
function get(path) { return fetch(path).then(function (r) { if (!r.ok) throw new Error(path + ' returned ' + r.status); return r.json(); }); }
// full=false (tab switch): fetch only what the tab being opened needs, to stay well inside the API rate limit.
function load(full) {
  var jobs = [];
  if (full !== false || tab === 'mints') jobs.push(get('/api/mints').then(function (d) { mints = d.mints; fillRules(); renderMints(); }), get('/api/stats').then(renderStats));
  if (tab === 'denied' || loaded.denied) jobs.push(get('/api/denials').then(function (d) { loaded.denied = true; renderDenials(d.denials); }));
  if (tab === 'cleanup') jobs.push(get('/api/cleanup').then(renderCleanup), get('/api/cleanup/trend?days=' + $('cl-range').value).then(renderTrend));
  if (tab === 'policy' && !loaded.policy) jobs.push(get('/api/policy').then(function (p) { loaded.policy = true; renderPolicy(p); }));
  return Promise.all(jobs).then(function () { $('error').hidden = true; $('updated').textContent = 'Updated ' + new Date().toLocaleTimeString(); })
    .catch(function (e) { $('error').textContent = 'Could not load data: ' + e.message; $('error').hidden = false; });
}
function setTab(name) {
  tab = name;
  loaded.policy = false;
  document.querySelectorAll('nav.tabs button').forEach(function (b) { b.className = b.getAttribute('data-tab') === name ? 'on' : ''; });
  ['mints', 'policy', 'denied', 'cleanup'].forEach(function (t) { $('tab-' + t).hidden = t !== name; });
  load(false);
}
document.querySelectorAll('nav.tabs button').forEach(function (b) { b.onclick = function () { setTab(b.getAttribute('data-tab')); }; });
['q', 'sort'].forEach(function (id) { $(id).oninput = renderMints; });
// One Filter button. Filters live in hidden selects (values kept in sync by fillRules); the panel adds one, the small list below shows and removes them.
var FILTERS = [['status', 'Status'], ['provider', 'Provider'], ['repo', 'Repo / identity'], ['subject', 'Subject'], ['rule', 'Rule'], ['perm', 'Permission'], ['range', 'Issued']];
function closeMenu() { $('fmenu').hidden = true; }
function fillValues() {
  var src = $($('fsel').value), val = $('fval');
  val.replaceChildren();
  Array.prototype.slice.call(src.options).forEach(function (o) { if (o.value) { var n = el('option', '', o.textContent); n.value = o.value; val.append(n); } });
  $('fadd').disabled = !val.options.length;
}
FILTERS.forEach(function (f) { var o = el('option', '', f[1]); o.value = f[0]; $('fsel').append(o); });
$('fsel').oninput = fillValues;
$('addf').onclick = function (ev) { ev.stopPropagation(); var m = $('fmenu'); m.hidden = !m.hidden; if (!m.hidden) fillValues(); };
$('fmenu').onclick = function (ev) { ev.stopPropagation(); };
document.addEventListener('click', closeMenu);
$('fadd').onclick = function () {
  var id = $('fsel').value, sel = $(id);
  sel.value = $('fval').value;
  if (id === 'provider') { $('repo').value = ''; $('subject').value = ''; fillRules(); } else if (id === 'repo') { $('subject').value = ''; fillRules(); }
  sel.value = $('fval').value;
  closeMenu(); renderMints();
};
function removeFilter(id) {
  $(id).value = '';
  if (id === 'provider') { $('repo').value = ''; $('subject').value = ''; fillRules(); } else if (id === 'repo') { $('subject').value = ''; fillRules(); }
  renderMints();
}
function renderActive() {
  var box = $('alist'), any = false;
  box.replaceChildren();
  function item(label, value, remove) {
    any = true;
    var s2 = el('span', 'af'), b = el('button', '', '\u00d7');
    s2.append(label + ': ', el('b', '', value), b); b.title = 'Remove'; b.onclick = remove; box.append(s2);
  }
  FILTERS.forEach(function (f) {
    var sel = $(f[0]);
    if (sel.value) item(f[1], sel.options[sel.selectedIndex] ? sel.options[sel.selectedIndex].textContent : sel.value, function () { removeFilter(f[0]); });
  });
  if ($('sort').value !== 'new') item('Sort', $('sort').options[$('sort').selectedIndex].textContent, function () { $('sort').value = 'new'; renderMints(); });
  $('reset').hidden = !any;
}
$('reset').onclick = function () { FILTERS.forEach(function (f) { $(f[0]).value = ''; }); $('q').value = ''; $('sort').value = 'new'; fillRules(); renderMints(); };
$('refresh').onclick = function () { load(); };
$('auto').onclick = function () { var on = $('auto').className !== 'on'; $('auto').className = on ? 'on' : ''; clearInterval(timer); if (on) timer = setInterval(load, 30000); };
$('theme').onclick = function () {
  var dark = document.documentElement.getAttribute('data-theme') === 'dark' || (!document.documentElement.getAttribute('data-theme') && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.setAttribute('data-theme', dark ? 'light' : 'dark');
  try { localStorage.setItem('cfsts-theme', dark ? 'light' : 'dark'); } catch (e) {}
};
try { var saved = localStorage.getItem('cfsts-theme'); if (saved) document.documentElement.setAttribute('data-theme', saved); } catch (e) {}
$('cl-range').oninput = function () { load(false); };
setInterval(function () { tick(); clock(); }, 1000);
timer = setInterval(load, 30000);
load();
</script></body></html>`;
