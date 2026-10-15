#!/usr/bin/env python3
"""
clo_audit.py -- one diagnosis-and-repair cycle of CLO over an inventory.

  Monitor   the inventory (Turtle / N-Triples), e.g. from tools/ingest_c7n.py
  Analyse   open world:   materialise with --engine (clo-r default; hermit, pellet, owlrl)
            closed world: rules/cwa/*.rq over the materialised graph, complete records only
  Plan      root-cause grouping, role attribution per governing policy, repairs
            (rename to the canonical key, inherit from a parent, team default
            under a dominance threshold, or ask the owner)
  Execute   tools/clo_compile.py turns the derived standard and the repairs into
            provider-native artefacts (not applied automatically)

Outputs in --out-dir: inferred.nt, findings.json, report.txt

  python3 tools/clo_audit.py --abox examples/company_example.ttl --out-dir out
"""
import argparse
import collections
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from clo import audit as A  # noqa: E402
from clo import kb  # noqa: E402


def report_text(rep):
    L = ["== Findings by root cause (closed world, complete records only)"]
    for f in rep["findings"]:
        what = f.get("key") or f.get("used") or f.get("value") or f.get("detail") or ""
        extra = f" missing {', '.join(f['missing'])}" if f.get("missing") else ""
        team = f" team {f['team']}" if f.get("team") else ""
        roles = f" for {', '.join(f['roles'])}" if f.get("roles") else ""
        rep_ = f" -> {f['repair']}" if f.get("repair") else (f" -> {f['suggestion']}?" if f.get("suggestion") else "")
        L.append(f"   {f['rule']:6} {f['severity']:7} {f.get('resource') or '':16} {what:22}{extra}{team}{roles}{rep_}")
    L.append("== Raw finding counts: " + json.dumps(rep["raw_counts"]))
    L.append("== Root-cause counts:  " + json.dumps(rep["root_cause_counts"]))
    L.append("== Role coverage (resources governed by a policy serving the role)")
    for c in rep["role_coverage"]:
        L.append(f"   {c['role']:22} {c['covered']}/{c['governed']}  needs {', '.join(c['keys'])}")
    L.append(f"== No closed-world verdict (record incomplete): {', '.join(rep['no_verdict']) or '-'}")
    L.append(f"== Out of audit scope (untaggable type): {', '.join(rep['out_of_scope']) or '-'}")
    L.append(f"== Labelling support unknown: {', '.join(rep['support_unknown']) or '-'}")
    return "\n".join(L)


def run(aboxes, out_dir, engine="clo-r", repair_policy="safe", timeout=None):
    os.makedirs(out_dir, exist_ok=True)
    t0 = time.perf_counter()
    g, info = kb.materialise(engine, aboxes, timeout=timeout)
    st = kb.as_store(g)
    t1 = time.perf_counter()
    au = A.Audit(st, repair_policy=repair_policy)
    raw = au.run()
    roots = au.root_causes(raw)
    rep = A.to_json(au, raw, roots)
    rep["cross_provider"] = au.cross_provider()
    rep["required_keys_by_policy"] = sorted(
        (A.loc(p), au.keyname.get(k, k)) for p, ks in au.pol_req.items() for k in ks)
    rep["timing"] = {"engine": engine, "materialise_s": round(t1 - t0, 3),
                     "audit_s": round(time.perf_counter() - t1, 3), **{k: v for k, v in info.items() if k != "stderr"}}
    json.dump(rep, open(os.path.join(out_dir, "findings.json"), "w"), indent=1, default=str)
    st.dump(os.path.join(out_dir, "inferred.nt"), format=kb.ox.RdfFormat.N_TRIPLES, from_graph=kb.ox.DefaultGraph())
    text = report_text(rep)
    open(os.path.join(out_dir, "report.txt"), "w").write(text + "\n")
    return rep, text


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--abox", nargs="+", default=[os.path.join(kb.ROOT, "examples", "company_example.ttl")])
    ap.add_argument("--out-dir", default="audit_out")
    ap.add_argument("--engine", default="clo-r", choices=["clo-r", "hermit", "pellet", "owlrl"])
    ap.add_argument("--repair-policy", default="safe", choices=["safe", "majority", "naive"])
    a = ap.parse_args()
    rep, text = run(a.abox, a.out_dir, a.engine, a.repair_policy)
    print(text)
    print("== timing", rep["timing"])
