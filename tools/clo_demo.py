#!/usr/bin/env python3
"""
clo_demo.py -- CLO Studio, the interactive demonstration of the diagnosis-and-repair cycle.

It runs the real pipeline (tools/clo_audit.py, tools/clo_compile.py) on the company example
under every combination of four what-if switches, extracts from each materialised graph the
derivation behind every requirement (which chain made a policy govern a resource, which role
made the policy require a key), and writes one self-contained HTML page (no network access
needed) that lets a reader

  * switch the scenario (a new role joins the standard, a role needs one more key, the
    local closed world is switched off, team-majority repairs instead of CLO's) and see what
    changes in the derived standard, the findings and the compiled artefacts;
  * look at the estate through one governance role;
  * open any finding and read its explanation: the property-chain path from the resource to
    the policy, the role that needs the key, the completeness verdict, and the repair with
    the value source that justifies it;
  * replay the closed loop and the repair-sensitivity sweep (results/rq5_*.json), and the
    open-corpus results (results/rq2_*.json, rq3_baselines.json).

Every number on the page comes from a CLO run or from results/*.json; the page computes nothing
that CLO did not.

  python3 tools/clo_demo.py --out examples/demo/clo_studio.html
  python3 tools/clo_demo.py --out /tmp/page.html --fragment     # body only (for embedding)
"""
import argparse
import collections
import itertools
import json
import os
import re
import sys
import tempfile

import rdflib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
from tools import clo_audit  # noqa: E402
import clo_compile  # noqa: E402

CLO = "http://example.org/clo/ontology/clo#"
C = rdflib.Namespace(CLO)
RDFS, RDF = rdflib.RDFS, rdflib.RDF
loc = lambda u: str(u).split("#")[-1]
EXAMPLE = os.path.join(ROOT, "examples", "company_example.ttl")
PREFIX = (f"@prefix clo: <{CLO}> .\n@prefix owl: <http://www.w3.org/2002/07/owl#> .\n"
          "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n")

SWITCHES = [
    {"id": "role", "label": "Sustainability joins the shared standard",
     "hint": "A new governance role needs carbon-scope; the shared policy now serves it. No rule is edited.",
     "ttl": 'clo:k_carbon a clo:LabelKey , owl:NamedIndividual ; clo:keyName "carbon-scope" .\n'
            'clo:SustainabilityRole a clo:GovernanceRole , owl:NamedIndividual ; rdfs:label "Sustainability" ; '
            'clo:needsLabel clo:k_carbon .\nclo:pol_shared clo:servesRole clo:SustainabilityRole .\n'},
    {"id": "key", "label": "Security also needs data-owner",
     "hint": "One more key for one role: every policy serving Security now requires it.",
     "ttl": 'clo:k_data_owner a clo:LabelKey , owl:NamedIndividual ; clo:keyName "data-owner" .\n'
            'clo:SecurityRole clo:needsLabel clo:k_data_owner .\n'},
    {"id": "closure", "label": "Close the world everywhere",
     "hint": "Treat every record as complete, as an export-based check does. vol-scratch's listing did not "
             "return its tags, so its absences become false findings."},
    {"id": "naive", "label": "Team-majority repairs",
     "hint": "Fill every missing key with the owning team's most frequent value (the 8.x policy), "
             "without value sources or a dominance threshold."},
]
RULES = {
    "I-07": "Missing required key", "I-11": "Unlabelled resource", "I-22": "Non-canonical spelling (rename)",
    "I-22r": "Redundant variant", "I-26": "No owning team", "I-27": "Several owning teams", "I-28": "Several types",
    "I-25": "Team convention differs from the shared key", "I-12": "Environment at risk", "I-09": "Value outside vocabulary",
    "I-13": "Case not allowed", "I-14": "Too long", "I-15": "Reserved prefix", "I-16": "Declared conflict",
    "I-17": "Unmanaged key", "I-20": "Edit-distance suggestion", "I-21": "Value available on a parent",
}
CHAINS = {"C-4": "organisational hierarchy", "C-8": "account policy", "C-11": "team policy",
          "C-3": "composition (partOf)", "C-5": "category policy", "C-9": "standard derived from role needs"}


def first(g, s, p, default=None):
    return next(g.objects(s, p), default)


def label(g, u):
    if u is None:
        return None
    rid = first(g, u, C.resourceId)
    return str(rid) if rid is not None else str(first(g, u, RDFS.label, loc(u)))


def explain(g):
    """Per resource: tags, governing policies with the chain that reached them, required keys."""
    T = RDF.type
    res = {}
    keyname = {k: str(n) for k, n in g.subject_objects(C.keyName)}
    roles_of = collections.defaultdict(set)
    for p, ro in g.subject_objects(C.servesRole):
        roles_of[p].add(ro)
    needs = collections.defaultdict(set)
    for ro, k in g.subject_objects(C.needsLabel):
        needs[ro].add(k)
    asserted_req = collections.defaultdict(set)   # requiresLabel not derived through a role
    for p, k in g.subject_objects(C.requiresLabel):
        if not any(k in needs[ro] for ro in roles_of[p]):
            asserted_req[p].add(k)
    for r in g.subjects(T, C.CloudResource):
        if first(g, r, C.resourceId) is None:
            continue
        tags = {}
        for l in g.objects(r, C.hasLabel):
            k = first(g, l, C.hasLabelKey)
            v = first(g, first(g, l, C.hasLabelValue), C.valueName)
            tags[keyname.get(k, loc(k))] = str(v) if v is not None else ""
        acct = first(g, r, C.belongsToAccount)
        teams = sorted(g.objects(r, C.ownedBy), key=str)
        gov = []
        for p in sorted(set(g.objects(r, C.governedBy)), key=str):
            paths = []
            if acct is not None and (acct, C.governedBy, p) in g:
                paths.append(("C-8", [[label(g, r), "belongsToAccount", label(g, acct)], [label(g, acct), "governedBy", label(g, p)]]))
            if acct is not None:
                for u in g.objects(acct, C.orgPartOf):
                    if (u, C.governedBy, p) in g:
                        paths.append(("C-4", [[label(g, r), "belongsToAccount", label(g, acct)],
                                              [label(g, acct), "orgPartOf", label(g, u)], [label(g, u), "governedBy", label(g, p)]]))
            for t in teams:
                if (t, C.governedBy, p) in g:
                    paths.append(("C-11", [[label(g, r), "ownedBy", label(g, t)], [label(g, t), "governedBy", label(g, p)]]))
            for q in g.objects(r, C.partOf):
                if (q, C.governedBy, p) in g:
                    paths.append(("C-3", [[label(g, r), "partOf", label(g, q)], [label(g, q), "governedBy", label(g, p)]]))
            for c in g.objects(r, C.belongsToCategory):
                if (p, C.appliesToCategory, c) in g:
                    paths.append(("C-5", [[label(g, r), "belongsToCategory", loc(c)], [label(g, p), "appliesToCategory", loc(c)]]))
            gov.append({"policy": label(g, p), "paths": [{"chain": c, "steps": s} for c, s in paths]})
        req = collections.defaultdict(list)
        for p in g.objects(r, C.governedBy):
            for ro in roles_of[p]:
                for k in needs[ro]:
                    req[keyname.get(k, loc(k))].append({"policy": label(g, p), "role": label(g, ro), "chain": "C-9"})
            for k in asserted_req[p]:
                req[keyname.get(k, loc(k))].append({"policy": label(g, p), "role": None, "chain": "asserted"})
        rt = first(g, r, C.hasResourceType)
        res[label(g, r)] = {
            "type": str(first(g, rt, C.resourceTypeName, loc(rt))) if rt is not None else None,
            "provider": loc(first(g, r, C.hostedBy)) if first(g, r, C.hostedBy) is not None else None,
            "category": loc(first(g, r, C.belongsToCategory)) if first(g, r, C.belongsToCategory) is not None else None,
            "account": label(g, acct), "teams": [label(g, t) for t in teams],
            "complete": str(first(g, r, C.recordComplete, "")) == "true",
            "in_scope": (r, T, C.AuditableResource) in g,
            "tags": tags, "governing": gov,
            "required": {k: sorted(v, key=lambda x: (x["policy"], x["role"] or "")) for k, v in sorted(req.items())},
        }
    pols = []
    for p in sorted(set(g.subjects(T, C.LabelingPolicy)), key=lambda x: label(g, x)):
        attached = [label(g, s) for s in g.subjects(C.governedBy, p)
                    if (s, T, C.CloudResource) not in g]
        cats = [loc(c) for c in g.objects(p, C.appliesToCategory)]
        pols.append({"policy": label(g, p), "attached_to": sorted(attached) + [f"category {c}" for c in cats],
                     "roles": sorted(label(g, ro) for ro in roles_of[p]),
                     "keys": sorted({keyname.get(k, loc(k)) for k in g.objects(p, C.requiresLabel)}),
                     "by_role": {label(g, ro): sorted(keyname.get(k, loc(k)) for k in needs[ro]) for ro in roles_of[p]},
                     "asserted": sorted(keyname.get(k, loc(k)) for k in asserted_req[p])})
    roles = [{"role": label(g, ro), "needs": sorted(keyname.get(k, loc(k)) for k in needs[ro]),
              "played_by": sorted(label(g, t) for t in g.subjects(C.playsRole, ro))}
             for ro in sorted(set(g.subjects(T, C.GovernanceRole)), key=lambda x: label(g, x))]
    vs = collections.defaultdict(list)
    for k, s in g.subject_objects(C.valueSource):
        vs[keyname.get(k, loc(k))].append(str(s))
    syn = []
    for sg in g.subjects(T, C.SynonymGroup):
        syn.append({"canonical": str(first(g, sg, C.canonicalKey, "")),
                    "members": sorted(keyname.get(k, loc(k)) for k in g.objects(sg, C.hasMember))})
    return res, pols, roles, {k: sorted(v) for k, v in vs.items()}, syn


def scenario(bits, wd):
    on = {s["id"] for s, b in zip(SWITCHES, bits) if b}
    tag = "".join(str(b) for b in bits)
    aboxes = []
    text = open(EXAMPLE).read()
    if "closure" in on:
        text = text.replace("clo:recordComplete false", "clo:recordComplete true")
    p = os.path.join(wd, f"ex_{tag}.ttl")
    open(p, "w").write(text)
    aboxes.append(p)
    extra = "".join(s["ttl"] for s in SWITCHES if s["id"] in on and s.get("ttl"))
    if extra:
        q = os.path.join(wd, f"extra_{tag}.ttl")
        open(q, "w").write(PREFIX + f"<{CLO}demo-{tag}> a owl:Ontology .\n" + extra)
        aboxes.append(q)
    out = os.path.join(wd, f"out_{tag}")
    rep, _ = clo_audit.run(aboxes, out, repair_policy="naive" if "naive" in on else "safe")
    g = rdflib.Graph()
    g.parse(os.path.join(out, "inferred.nt"), format="nt")
    res, pols, roles, vs, syn = explain(g)
    # Execute step: the compiled artefacts for this scenario
    import pyoxigraph as ox
    st = ox.Store()
    st.bulk_load(path=os.path.join(out, "inferred.nt"), format=ox.RdfFormat.N_TRIPLES)
    aws, az, c7n, cov = clo_compile.compile_graph(st)
    import yaml
    enforce = {"aws_config.json": json.dumps(aws, indent=1), "azure_policy.json": json.dumps(az, indent=1),
               "custodian.yml": yaml.safe_dump({"policies": c7n}, sort_keys=False),
               "repairs.sh": clo_compile.repairs(rep), "coverage.json": json.dumps(cov, indent=1)}
    repairs_by_res = collections.defaultdict(list)
    lines = enforce["repairs.sh"].splitlines()
    for i, l in enumerate(lines):
        m = re.match(r"# (\S+): (.*)", l)
        if m and i + 1 < len(lines):
            repairs_by_res[m.group(1)].append({"what": m.group(2), "cmd": lines[i + 1]})
    fnd = []
    for f in rep["findings"]:
        fnd.append({k: f.get(k) for k in ("rule", "severity", "resource", "key", "roles", "repair", "repair_action",
                                          "repair_value", "missing", "used", "team", "canonical", "value", "n", "bad")})
    return {"on": sorted(on), "findings": fnd, "raw_counts": rep["raw_counts"], "root_counts": rep["root_cause_counts"],
            "coverage": rep["role_coverage"], "no_verdict": rep["no_verdict"], "out_of_scope": rep["out_of_scope"],
            "resources": res, "policies": pols, "roles": roles, "value_source": vs, "synonyms": syn,
            "enforce": enforce, "enforce_coverage": cov, "repairs_by_resource": repairs_by_res}


def results(rdir):
    def load(n):
        p = os.path.join(rdir, n)
        return json.load(open(p)) if os.path.exists(p) else None
    out = {}
    loop = load("rq5_loop.json")
    if loop:
        series = {}
        for pol, runs in loop["runs"].items():
            rows = []
            for c in range(len(runs[0])):
                xs = [h[c] for h in runs]
                mean = lambda k: sum(x[k] for x in xs) / len(xs)
                rows.append({"cycle": c, "open": round(mean("open_errors")), "keys": round(100 * mean("compliant") / mean("in_scope"), 1),
                             "true": round(100 * mean("correct") / mean("in_scope"), 1), "wrong": round(mean("silent_wrong_values"))})
            series[pol] = rows
        out["loop"] = {"params": loop["params"], "series": series, "seeds": len(loop["runs"]["safe"])}
    sens = load("rq5_sensitivity.json")
    if sens:
        out["sensitivity"] = sens
    rq2 = load("rq2_real.json")
    if rq2:
        i = rq2["ingest"]
        out["corpus"] = {"resources": i["resources"], "by_provider": i["by_provider"], "rules": i["completeness_rule"],
                         "rule_text": i.get("rules", {}), "spellings": rq2["spellings"], "export": rq2["export_checks"],
                         "i17_top": rq2.get("i17_top_keys"), "coverage_top_level": rq2.get("coverage_top_level"),
                         "root_counts": rq2["root_cause_counts"]}
    val = load("rq2_completeness.json")
    if val:
        out["validation"] = {k: v for k, v in val.items() if k != "examples"}
    rq3 = load("rq3_baselines.json")
    if rq3:
        out["baselines"] = {k: {x: v.get(x) for x in ("precision", "recall", "recall_flat", "fp", "fn")}
                            for k, v in rq3["aggregate"].items()}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "examples", "demo", "clo_studio.html"))
    ap.add_argument("--results", default=os.path.join(ROOT, "results"))
    ap.add_argument("--fragment", action="store_true", help="write the page body only (no <html>/<head>)")
    a = ap.parse_args()
    wd = tempfile.mkdtemp()
    scen = {}
    for bits in itertools.product([0, 1], repeat=len(SWITCHES)):
        scen["".join(map(str, bits))] = scenario(bits, wd)
        print("scenario", "".join(map(str, bits)), scen["".join(map(str, bits))]["root_counts"], flush=True)
    data = {"switches": [{k: s[k] for k in ("id", "label", "hint")} for s in SWITCHES], "rules": RULES, "chains": CHAINS,
            "scenarios": scen, "results": results(a.results)}
    tpl = open(os.path.join(HERE, "demo_template.html")).read()
    blob = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    page = tpl.replace("/*__CLO_DATA__*/null", blob)
    if not a.fragment:
        page = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
                '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
                + page.replace("</style>", "</style>\n</head>\n<body>", 1) + "\n</body>\n</html>\n")
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    open(a.out, "w").write(page)
    print(f"wrote {a.out} ({len(page) // 1024} KiB, {len(scen)} scenarios)")


if __name__ == "__main__":
    main()
