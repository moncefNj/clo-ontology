#!/usr/bin/env python3
"""
clo_viz.py -- interactive viewer for one CLO audit cycle.

Reads the output of tools/clo_audit.py (inferred.nt, findings.json) and
writes a single self-contained HTML file (cytoscape.js is embedded, so it
works offline). The layout reads left to right as the governance chain:

  policies -> governance roles -> label keys <- resources -> teams -> providers

"View as" switches the lens to one role (FinOps, Security, ...): the keys that
role needs, the resources that miss them, and the repairs proposed. Inferred
edges (dashed) can be toggled: required keys derived from roles (C-9), the
provider of each resource (C-1).

  python3 tools/clo_audit.py --out-dir audit_out
  python3 tools/clo_viz.py --in-dir audit_out --out audit_out/clo_view.html
"""
import argparse
import html
import json
import os
from collections import defaultdict

import rdflib

HERE = os.path.dirname(os.path.abspath(__file__))
CLO = "http://example.org/clo/ontology/clo#"
C = rdflib.Namespace(CLO)
RDFS = rdflib.RDFS
loc = lambda u: str(u).split("#")[-1]


def build(in_dir):
    g = rdflib.Graph(); g.parse(os.path.join(in_dir, "inferred.nt"), format="nt")
    fd = json.load(open(os.path.join(in_dir, "findings.json")))
    label = lambda u, d=None: str(next(g.objects(u, RDFS.label), d or loc(u)))
    T = rdflib.RDF.type

    roles = sorted(set(g.subjects(T, C.GovernanceRole)), key=lambda r: label(r))
    root_pols = {p for o in g.subjects(T, C.OrganizationalRoot) for p in g.objects(o, C.governedBy)}
    policies = sorted(set(g.subjects(T, C.LabelingPolicy)), key=lambda p: (p not in root_pols, loc(p)))
    teams = sorted(set(g.subjects(T, C.Team)), key=lambda t: label(t))
    resources = [r for r in g.subjects(T, C.CloudResource) if (r, C.resourceId, None) in g]
    key_name = {k: str(n) for k, n in g.subject_objects(C.keyName)}
    canonical = {}
    for sg in g.subjects(T, C.SynonymGroup):
        canon = str(next(g.objects(sg, C.canonicalKey), ""))
        for k in g.objects(sg, C.hasMember):
            canonical[k] = canon

    # status per resource
    by_res = defaultdict(list)
    KIND = {"I-07": "missing required key", "I-22": "non-canonical key", "I-11": "unlabelled",
            "I-26": "no owning team", "I-27": "several owning teams", "I-28": "several types"}
    for f in fd["findings"]:
        if not f.get("iri"):
            continue
        f = dict(f, kind=KIND.get(f["rule"], f["rule"]), roles=f.get("roles") or ["all"],
                 repair=f.get("repair") or (f"missing {', '.join(f['missing'])}" if f.get("missing") else "-"))
        by_res[f["iri"]].append(f)
    no_verdict = set(fd["no_verdict"])
    out_scope = {s.split(" (")[0] for s in fd["out_of_scope"]}

    def status(r):
        rid = str(next(g.objects(r, C.resourceId)))
        fs = by_res.get(str(r), [])
        if rid in out_scope:
            return "outofscope"
        if rid in no_verdict:
            return "noverdict"
        if any(f["kind"] in ("unlabelled", "no owning team") for f in fs):
            return "critical"
        return "findings" if fs else "ok"

    owner = {r: t for r, t in g.subject_objects(C.ownedBy)}
    team_order = {t: i for i, t in enumerate(teams)}
    resources.sort(key=lambda r: (team_order.get(owner.get(r), 99), str(next(g.objects(r, C.resourceId)))))

    # keys: the ones roles need, then the ones used on resources
    used_keys = defaultdict(set)
    for r in resources:
        for l in g.objects(r, C.hasLabel):
            for k in g.objects(l, C.hasLabelKey):
                used_keys[r].add(k)
    needed = [(ro, k) for ro in roles for k in g.objects(ro, C.needsLabel)]
    keys = []
    for _, k in needed:
        if k not in keys:
            keys.append(k)
    for r in resources:
        for k in sorted(used_keys[r], key=lambda k: key_name.get(k, "")):
            if k not in keys:
                keys.append(k)

    nodes, edges = [], []
    X = {"policy": 0, "role": 220, "key": 470, "resource": 760, "team": 1040, "provider": 1250}

    def spread(items, top=0, step=56):
        return {it: top + i * step for i, it in enumerate(items)}

    y_res = spread(resources, 0, 66)
    y_key = spread(keys, 10, 78)
    # align roles with their first key, teams with their resources
    y_role = {}
    for ro in roles:
        ks = [y_key[k] for k in g.objects(ro, C.needsLabel) if k in y_key]
        y_role[ro] = sum(ks) / len(ks) if ks else 0
    y_team = {}
    for t in teams:
        ys = [y_res[r] for r in resources if owner.get(r) == t]
        y_team[t] = sum(ys) / len(ys) if ys else max(y_res.values()) + 60
    y_pol = spread(policies, 90, 260)
    provs = sorted({p for r in resources for p in g.objects(r, C.hostedBy)}, key=loc)
    y_prov = spread(provs, 60, 150)
    root = next(g.subjects(T, C.OrganizationalRoot), None)

    def node(i, lab, kind, x, y, **extra):
        nodes.append({"data": {"id": i, "label": lab, "kind": kind, **extra}, "position": {"x": x, "y": y}})

    if root is not None:
        node(loc(root), label(root), "org", X["policy"], -10)
    for p in policies:
        req = sorted(key_name.get(k, loc(k)) for k in g.objects(p, C.requiresLabel))
        node(loc(p), label(p), "policy", X["policy"], y_pol[p], requires=req)
    for ro in roles:
        node(loc(ro), label(ro), "role", X["role"], y_role[ro],
             needs=sorted(key_name.get(k, loc(k)) for k in g.objects(ro, C.needsLabel)))
    for k in keys:
        nm = key_name.get(k, loc(k))
        alias = canonical.get(k) if canonical.get(k) and canonical.get(k) != nm else None
        node(loc(k), nm + (f" ≈ {alias}" if alias else ""), "key", X["key"], y_key[k],
             noncanonical=bool(alias))
    for r in resources:
        rid = str(next(g.objects(r, C.resourceId)))
        cat = next((label(c) for c in g.objects(r, C.belongsToCategory)), "")
        prov = next((loc(p) for p in g.objects(r, C.hostedBy)), "")
        typ = next((str(n) for t in g.objects(r, C.hasResourceType) for n in g.objects(t, C.resourceTypeName)), "")
        node(loc(r), f"{rid}\n{prov} · {cat}", "resource", X["resource"], y_res[r],
             status=status(r), rtype=typ, findings=by_res.get(str(r), []),
             team=label(owner[r]) if r in owner else None,
             policies=sorted(label(p) for p in g.objects(r, C.governedBy)))
    for t in teams:
        node(loc(t), label(t), "team", X["team"], y_team[t],
             roles=sorted(label(ro) for ro in g.objects(t, C.playsRole)),
             uses=sorted(key_name.get(k, loc(k)) for k in g.objects(t, C.usesKey)))
    for p in provs:
        node(loc(p), loc(p), "provider", X["provider"], y_prov[p])

    eid = iter(range(10 ** 6))
    def edge(s, t, kind, **extra):
        edges.append({"data": {"id": f"e{next(eid)}", "source": s, "target": t, "kind": kind, **extra}})

    if root is not None:
        for p in g.objects(root, C.governedBy):
            if (p, T, C.LabelingPolicy) in g:
                edge(loc(root), loc(p), "governs")
    for p in policies:
        for ro in g.objects(p, C.servesRole):
            edge(loc(p), loc(ro), "serves")
        for k in g.objects(p, C.requiresLabel):
            edge(loc(p), loc(k), "requires")          # inferred, C-9
    for ro, k in needed:
        edge(loc(ro), loc(k), "needs")
    for r in resources:
        for k in used_keys[r]:
            edge(loc(r), loc(k), "has")
        for f in by_res.get(str(r), []):
            names = [f["key"]] if f["kind"] in ("missing required key", "non-canonical key") else \
                (f.get("missing") or []) if f["kind"] == "unlabelled" else []
            for nm in names:
                kk = next((k for k, n in key_name.items() if n == nm), None)
                if kk is not None:
                    edge(loc(r), loc(kk), "missing", roles=f["roles"])
        if r in owner:
            edge(loc(r), loc(owner[r]), "owned")
        for p in g.objects(r, C.hostedBy):
            edge(loc(r), loc(p), "hosted")             # inferred, C-1
    for t in teams:
        for p in g.objects(t, C.governedBy):
            if (p, T, C.LabelingPolicy) in g:
                edge(loc(t), loc(p), "teampolicy")
    for k, canon in canonical.items():
        tgt = next((kk for kk, n in key_name.items() if n == canon), None)
        if tgt is not None and tgt != k:
            edge(loc(k), loc(tgt), "synonym")

    summary = {
        "resources": len(resources),
        "in_scope": len(resources) - len(out_scope),
        "complete": len(resources) - len(out_scope) - len(no_verdict),
        "findings": len(fd["findings"]),
        "teams": len(teams), "roles": len(roles),
        "coverage": [dict(c, resources=c["governed"]) for c in fd["role_coverage"] if c["governed"]],
        "conventions": [{"team": f["team"], "uses": f["used"], "canonical": f["canonical"]}
                        for f in fd["findings"] if f["rule"] == "I-25"],
        "required": fd.get("required_keys_by_policy", []),
    }
    return {"nodes": nodes, "edges": edges, "summary": summary,
            "roles": [label(r) for r in roles]}


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CLO Inventory Explorer</title>
<style>
:root{--bg:#f7f7f5;--panel:#ffffff;--ink:#1d2433;--mute:#5d6577;--line:#d9dbe1;
 --inv:#dce6f2;--lab:#e3f0da;--gov:#fbe5d0;--org:#ececec;
 --ok:#2e7d4f;--warn:#c77a12;--bad:#b3261e;--accent:#2f4b7c}
*{box-sizing:border-box}html,body{margin:0;height:100%;background:var(--bg);color:var(--ink);
 font:13px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{display:flex;align-items:baseline;gap:14px;padding:10px 16px;border-bottom:1px solid var(--line);background:var(--panel)}
header h1{font-size:15px;margin:0;font-weight:650}
header .chips{display:flex;gap:8px;flex-wrap:wrap}
.chip{padding:2px 8px;border:1px solid var(--line);border-radius:10px;color:var(--mute);font-size:12px}
main{display:grid;grid-template-columns:1fr 330px;height:calc(100% - 46px)}
#cy{width:100%;height:100%;background:var(--bg)}
aside{border-left:1px solid var(--line);background:var(--panel);overflow:auto;padding:12px 14px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--mute);margin:14px 0 6px}
.seg{display:flex;flex-wrap:wrap;gap:4px}
.seg button{border:1px solid var(--line);background:#fff;border-radius:6px;padding:3px 8px;font:inherit;cursor:pointer}
.seg button[aria-pressed=true]{background:var(--accent);color:#fff;border-color:var(--accent)}
label.tg{display:flex;gap:6px;align-items:center;margin:3px 0;color:var(--ink)}
.bar{height:8px;background:#eee;border-radius:4px;overflow:hidden;margin:2px 0 8px}
.bar i{display:block;height:100%;background:var(--accent)}
.f{border-top:1px solid #eee;padding:6px 0}
.f b{font-weight:600}.f .k{font-family:ui-monospace,Menlo,monospace;font-size:12px}
.f .r{color:var(--mute)}
.legend span{display:inline-flex;align-items:center;gap:5px;margin:2px 10px 2px 0}
.sw{width:12px;height:12px;border-radius:3px;border:1px solid #888;display:inline-block}
#detail{font-size:12px;color:var(--ink);white-space:pre-wrap}
@media (max-width:820px){main{grid-template-columns:1fr;grid-template-rows:60vh auto}aside{border-left:0;border-top:1px solid var(--line)}}
</style></head><body>
<header><h1>CLO Inventory Explorer</h1><div class="chips" id="chips"></div></header>
<main><div id="cy" role="img" aria-label="Governance graph"></div>
<aside>
 <h2>View as</h2><div class="seg" id="lens"></div>
 <h2>Show</h2>
 <label class="tg"><input type="checkbox" id="t_req" checked> required keys derived from roles (C-9)</label>
 <label class="tg"><input type="checkbox" id="t_has" checked> labels present</label>
 <label class="tg"><input type="checkbox" id="t_host"> provider of each resource (C-1)</label>
 <h2>Coverage</h2><div id="cov"></div>
 <h2>Findings and repairs</h2><div id="fl"></div>
 <h2>Team conventions</h2><div id="conv"></div>
 <h2>Selection</h2><div id="detail">Click a node.</div>
 <h2>Legend</h2><div class="legend">
  <span><i class="sw" style="background:#e6f4ea;border-color:var(--ok)"></i>compliant</span>
  <span><i class="sw" style="background:#fff3e0;border-color:var(--warn)"></i>findings</span>
  <span><i class="sw" style="background:#fde8e6;border-color:var(--bad)"></i>critical</span>
  <span><i class="sw" style="background:#fff;border-style:dashed"></i>no verdict</span>
  <span><i class="sw" style="background:#f2f2f2"></i>out of scope</span><br>
  <span>— label present</span><span style="color:var(--bad)">- - missing key</span><span>- - inferred</span>
 </div>
</aside></main>
<script>__CYTOSCAPE__</script>
<script>
const DATA = __DATA__;
const css = getComputedStyle(document.documentElement);
const col = n => css.getPropertyValue(n).trim();
document.getElementById('chips').innerHTML =
 [`${DATA.summary.resources} resources`,`${DATA.summary.in_scope} in audit scope`,
  `${DATA.summary.complete} with a complete record`,`${DATA.summary.findings} findings`,`${DATA.summary.teams} teams`,`${DATA.summary.roles} governance roles`]
 .map(t=>`<span class="chip">${t}</span>`).join('');
const statusFill={ok:'#e6f4ea',findings:'#fff3e0',critical:'#fde8e6',noverdict:'#ffffff',outofscope:'#f2f2f2'};
const statusLine={ok:col('--ok'),findings:col('--warn'),critical:col('--bad'),noverdict:'#888',outofscope:'#aaa'};
const cy = cytoscape({container:document.getElementById('cy'), elements:[...DATA.nodes,...DATA.edges],
 layout:{name:'preset',padding:30}, wheelSensitivity:0.25, autoungrabify:false,
 style:[
  {selector:'node',style:{'label':'data(label)','font-size':11,'text-wrap':'wrap','text-max-width':150,
     'text-valign':'center','text-halign':'center','shape':'round-rectangle','width':'label','height':'label',
     'padding':'7px','border-width':1,'border-color':'#7a8191','background-color':'#fff','color':'#1d2433',
     'font-family':'system-ui, sans-serif'}},
  {selector:'node[kind="policy"], node[kind="org"]',style:{'background-color':col('--gov'),'font-weight':600}},
  {selector:'node[kind="role"]',style:{'background-color':col('--gov'),'shape':'ellipse','padding':'9px'}},
  {selector:'node[kind="key"]',style:{'background-color':col('--lab'),'font-family':'ui-monospace, Menlo, monospace'}},
  {selector:'node[?noncanonical]',style:{'border-color':col('--warn'),'border-width':2}},
  {selector:'node[kind="team"]',style:{'background-color':col('--org'),'font-weight':600}},
  {selector:'node[kind="provider"]',style:{'background-color':col('--inv')}},
  {selector:'node[kind="resource"]',style:{'background-color':e=>statusFill[e.data('status')],
     'border-color':e=>statusLine[e.data('status')],'border-width':2,'font-size':10.5}},
  {selector:'node[status="noverdict"]',style:{'border-style':'dashed'}},
  {selector:'edge',style:{'width':1,'line-color':'#9aa1ad','target-arrow-color':'#9aa1ad',
     'target-arrow-shape':'triangle','arrow-scale':0.7,'curve-style':'bezier'}},
  {selector:'edge[kind="has"]',style:{'line-color':'#c4c8cf','target-arrow-shape':'none'}},
  {selector:'edge[kind="missing"]',style:{'line-color':col('--bad'),'target-arrow-color':col('--bad'),
     'line-style':'dashed','width':1.6}},
  {selector:'edge[kind="requires"], edge[kind="hosted"]',style:{'line-style':'dashed','line-color':'#6b7486',
     'target-arrow-color':'#6b7486'}},
  {selector:'edge[kind="synonym"]',style:{'line-style':'dotted','line-color':col('--warn'),
     'target-arrow-color':col('--warn'),'label':'synonym','font-size':9,'color':col('--warn'),
     'curve-style':'unbundled-bezier','control-point-distances':[-40],'control-point-weights':[0.5],
     'source-label':'synonym','label':'','source-text-offset':38,'text-background-color':'#ffffff',
     'text-background-opacity':1,'text-background-padding':2}},
  {selector:'edge[kind="teampolicy"]',style:{'curve-style':'unbundled-bezier','control-point-distances':[160],
     'control-point-weights':[0.5],'line-color':'#b38a5a','target-arrow-color':'#b38a5a'}},
  {selector:'.dim',style:{'opacity':0.12}},
  {selector:'.hidden',style:{'display':'none'}},
  {selector:':selected',style:{'border-width':3,'border-color':col('--accent')}}
 ]});
function setToggles(){
 const vis=(k,on)=>cy.edges(`[kind="${k}"]`).toggleClass('hidden',!on);
 vis('requires',document.getElementById('t_req').checked);
 vis('has',document.getElementById('t_has').checked);
 const h=document.getElementById('t_host').checked; vis('hosted',h);
 cy.nodes('[kind="provider"]').toggleClass('hidden',!h);
}
['t_req','t_has','t_host'].forEach(id=>document.getElementById(id).addEventListener('change',setToggles));
let lens='All';
function render(){
 cy.elements().removeClass('dim');
 const fsAll=DATA.nodes.filter(n=>n.data.kind==='resource').flatMap(n=>n.data.findings.map(f=>({...f,node:n.data})));
 let fs=fsAll;
 if(lens!=='All'){
  const role=cy.nodes(`[kind="role"]`).filter(n=>n.data('label')===lens);
  const needed=role.outgoers('edge[kind="needs"]').targets();
  const syn=cy.edges('[kind="synonym"]').filter(e=>needed.contains(e.target()));
  const keys=needed.union(syn.sources());
  const miss=cy.edges('[kind="missing"]').filter(e=>keys.contains(e.target()));
  const keep=role.union(keys).union(role.outgoers('edge[kind="needs"]')).union(miss).union(miss.sources())
    .union(cy.edges('[kind="has"]').filter(e=>keys.contains(e.target())))
    .union(cy.edges('[kind="has"]').filter(e=>keys.contains(e.target())).sources())
    .union(role.incomers('edge[kind="serves"]')).union(role.incomers('edge[kind="serves"]').sources()).union(syn);
  cy.elements().not(keep).addClass('dim');
  fs=fsAll.filter(f=>f.roles.includes(lens)||f.roles.includes('all'));
 }
 document.getElementById('fl').innerHTML = fs.length? fs.map(f=>
   `<div class="f"><b>${f.resource}</b> <span class="r">· ${f.node.team||'no team'}</span><br>
    ${f.kind}${f.key?` <span class="k">${f.key}</span>`:''} <span class="r">(${f.roles.join(', ')})</span><br>
    <span class="r">repair:</span> ${f.repair}</div>`).join('') : '<div class="f">No finding for this role.</div>';
 const cov=DATA.summary.coverage.filter(c=>lens==='All'||c.role===lens);
 document.getElementById('cov').innerHTML=cov.map(c=>`<div>${c.role}: ${c.covered}/${c.resources} resources carry every key it needs</div>
   <div class="bar"><i style="width:${100*c.covered/c.resources}%"></i></div>`).join('');
}
const lensEl=document.getElementById('lens');
['All',...DATA.roles].forEach(r=>{const b=document.createElement('button');b.textContent=r;
 b.setAttribute('aria-pressed',r===lens);b.onclick=()=>{lens=r;[...lensEl.children].forEach(x=>x.setAttribute('aria-pressed',x===b));render();};
 lensEl.appendChild(b);});
document.getElementById('conv').innerHTML = DATA.summary.conventions.length ?
 DATA.summary.conventions.map(c=>`<div class="f">${c.team} uses <span class="k">${c.uses}</span>; shared standard: <span class="k">${c.canonical}</span></div>`).join('')
 : '<div class="f">All teams follow the shared keys.</div>';
cy.on('tap','node',e=>{const d=e.target.data();const lines=[d.label.replace('\n',' — ')];
 if(d.kind==='resource'){lines.push(`type: ${d.rtype}`,`owning team: ${d.team||'none'}`,`status: ${d.status}`,
   `governed by (inferred): ${d.policies.join(', ')||'-'}`);}
 if(d.kind==='policy')lines.push(`requires (derived, C-9): ${d.requires.join(', ')}`);
 if(d.kind==='role')lines.push(`needs: ${d.needs.join(', ')}`);
 if(d.kind==='team')lines.push(`plays: ${d.roles.join(', ')}`,`uses keys (C-10): ${d.uses.join(', ')}`);
 document.getElementById('detail').textContent=lines.join('\n');});
const params=new URLSearchParams(location.search);
if(params.get('lens')){lens=params.get('lens');[...lensEl.children].forEach(x=>x.setAttribute('aria-pressed',x.textContent===lens));}
if(params.get('hosted')==='1')document.getElementById('t_host').checked=true;
if(params.get('fig')==='1'){document.querySelector('header').style.display='none';
 document.querySelector('aside').style.display='none';document.querySelector('main').style.cssText='display:block;height:100%';
 cy.resize(); cy.style().selector('node').style({'font-size':19,'text-max-width':260}).selector('node[kind="resource"]').style('font-size',18)
  .selector('edge[kind="synonym"]').style('font-size',16).selector('.dim').style('opacity',0.07).update(); cy.fit(undefined,12);}
setToggles(); render(); cy.fit(undefined,30);
window.__ready=true;
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-dir", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    data = build(a.in_dir)
    lib = open(os.path.join(HERE, "vendor", "cytoscape.min.js")).read()
    page = PAGE.replace("__CYTOSCAPE__", lib).replace(
        "__DATA__", json.dumps(data).replace("</", "<\\/"))
    open(a.out, "w").write(page)
    print(f"wrote {a.out}: {len(data['nodes'])} nodes, {len(data['edges'])} edges")


if __name__ == "__main__":
    main()
