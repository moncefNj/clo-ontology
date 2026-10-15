#!/usr/bin/env python3
"""
real_data.py -- RQ2: CLO on an open corpus of recorded provider responses.

Input: the inventory built by tools/ingest_c7n.py from Cloud Custodian's recorded
AWS, Azure and GCP API responses. This script adds the organisational context a
company would supply and runs the cycle:

  * one organisational root; every account / subscription / project is part of it;
  * the shared standard of the running example (FinOps, Security, Operations) plus
    Development's app key, attached at the root;
  * declared synonym groups and vocabularies identical to the synthetic estates;
  * ownership derived from the owner tag (any variant spelling), one team per
    (pseudonymised) owner value -- tag-derived ownership, as a CMDB merge would give. This is
    declared (clo:ownershipFromKey), so a missing owner key and "no owning team" are grouped
    as one root cause (9.0 counted both).

It reports the catalogue coverage, the completeness verdicts, the findings, the
observed spellings of the managed keys, the engines' agreement, and what the
baselines would report on records that carry no closed-world verdict.

  python3 eval/real_data.py --inventory data/open/c7n_inventory.ttl \
      --json data/open/c7n_inventory.json --out results/rq2_real.json
"""
import argparse
import collections
import hashlib
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
from clo import audit as A  # noqa: E402
from clo import kb  # noqa: E402
from tools import clo_audit  # noqa: E402

CLO = kb.CLO
H = lambda s: hashlib.sha256(s.encode()).hexdigest()[:12]
ROLES = {"FinOpsRole": ["cost-center"], "SecurityRole": ["data-classification"],
         "OperationsRole": ["owner", "environment"], "DeveloperRole": ["app"]}
SYNONYMS = {"environment": ["env", "stage"], "cost-center": ["costcentre"], "owner": ["contact"]}
VOCAB = {"environment": ["prod", "staging", "dev"], "data-classification": ["public", "internal", "confidential", "restricted"]}
VALUE_SOURCE = {"cost-center": ["inherit", "team-default"], "environment": ["inherit", "account-default"],
                "owner": ["inherit"], "app": ["inherit", "team-default"]}


def org_ttl(rows):
    L = [f"@prefix clo: <{CLO}> .", "@prefix owl: <http://www.w3.org/2002/07/owl#> .",
         "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .", "",
         "<http://example.org/clo/data/c7n-org> a owl:Ontology .",
         'clo:org_root a clo:OrganizationalRoot , owl:NamedIndividual ; rdfs:label "Company" ; clo:governedBy clo:pol_shared .',
         'clo:pol_shared a clo:LabelingPolicy , owl:NamedIndividual ; rdfs:label "Shared labelling standard" ; '
         "clo:servesRole clo:FinOpsRole , clo:SecurityRole , clo:OperationsRole , clo:DeveloperRole ."]
    k = lambda name: f"clo:k_{H(name)}"
    names = set()
    for role, ks in ROLES.items():
        for x in ks:
            L.append(f"clo:{role} clo:needsLabel {k(x)} .")
            names.add(x)
    for c, syns in SYNONYMS.items():
        L.append(f'clo:syn_{c.replace("-", "_")} a clo:SynonymGroup , owl:NamedIndividual ; clo:canonicalKey "{c}" ; '
                 "clo:hasMember " + " , ".join(k(x) for x in [c] + syns) + " .")
        names |= {c, *syns}
    for key, allowed in VOCAB.items():
        v = f"clo:voc_{key.replace('-', '_')}"
        L.append(f"{v} a clo:LabelVocabulary , owl:NamedIndividual . {k(key)} clo:hasVocabulary {v} .")
        for i, a in enumerate(allowed):
            L.append(f'clo:av_{key.replace("-", "_")}_{i} a clo:AllowedValue , owl:NamedIndividual ; clo:valueName "{a}" . '
                     f"{v} clo:hasAllowedValue clo:av_{key.replace('-', '_')}_{i} .")
    for key, srcs in VALUE_SOURCE.items():
        for s in srcs:
            L.append(f'{k(key)} clo:valueSource "{s}" .')
    for n in sorted(names):
        L.append(f'{k(n)} a clo:LabelKey , owl:NamedIndividual ; clo:keyName "{n}" .')
    accts = sorted({r["account"] for r in rows})
    for a in accts:
        L.append(f"clo:{a} clo:orgPartOf clo:org_root .")
    L.append(f"clo:org_root clo:ownershipFromKey {k('owner')} .")
    teams = {}
    for r in rows:
        owners = {v for kk, v in r["tags"].items() if A.norm(kk) == "owner"}
        for o in sorted(owners):
            t = teams.setdefault(o, f"clo:team_{H(o)}")
            L.append(f"clo:{r['iri']} clo:ownedBy {t} .")
    for o, t in sorted(teams.items()):
        L.append(f'{t} a clo:Team , owl:NamedIndividual ; rdfs:label "owner {o}" .')
    return "\n".join(L) + "\n", len(teams)


def baseline_pairs(rows, required, managed_norm):
    """What an export-based check (OPA-idiom; Custodian/Config semantics on the same records) reports:
    required canonical keys absent, on every in-scope record, complete or not."""
    out = collections.defaultdict(set)
    for r in rows:
        if not r["in_scope"]:
            continue
        for k in required:
            if k not in r["tags"]:
                out["exact"].add((r["id"], k))
                if r["provider"] == "Azure" and any(x.lower() == k for x in r["tags"]):
                    continue
                out["native_semantics"].add((r["id"], k))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--json", required=True)
    ap.add_argument("--report", default=os.path.join(ROOT, "data", "open", "c7n_ingest_report.json"))
    ap.add_argument("--report-noext", default=os.path.join(ROOT, "data", "open", "c7n_ingest_report_noext.json"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--dl", action="store_true", help="also compare HermiT and Pellet on this inventory")
    ap.add_argument("--keep-engines", action="store_true", help="without --dl: keep the engine comparison in --out")
    a = ap.parse_args()
    rows = json.load(open(a.json))
    wd = tempfile.mkdtemp()
    org, nteams = org_ttl(rows)
    orgp = os.path.join(wd, "org.ttl")
    open(orgp, "w").write(org)
    rep, text = clo_audit.run([a.inventory, orgp], os.path.join(wd, "audit"))
    res = rep["resources"]
    scope = {v["id"]: v["in_scope"] for v in res.values()}
    for r in rows:
        r["in_scope"] = scope.get(r["id"], False)
    out = {"ingest": json.load(open(a.report)), "ingest_noext": json.load(open(a.report_noext)),
           "teams_from_owner_tags": nteams, "raw_counts": rep["raw_counts"], "root_cause_counts": rep["root_cause_counts"],
           "role_coverage": rep["role_coverage"], "no_verdict": len(rep["no_verdict"]),
           "out_of_scope": len(rep["out_of_scope"]), "support_unknown": len(rep["support_unknown"]),
           "in_scope": sum(1 for v in res.values() if v["in_scope"]), "timing": rep["timing"],
           "cross_provider": rep["cross_provider"]}
    # observed spellings of the managed keys
    spell = collections.defaultdict(collections.Counter)
    variants = {A.norm(x): c for c, syns in SYNONYMS.items() for x in [c] + syns}
    variants.update({A.norm(x): x for ks in ROLES.values() for x in ks})
    for r in rows:
        for k in r["tags"]:
            c = variants.get(A.norm(k))
            if c:
                spell[c][k] += 1
    out["spellings"] = {c: dict(v.most_common()) for c, v in spell.items()}
    i17 = [f for f in rep["findings"] if f["rule"] == "I-17"]
    out["i17_distinct_keys"] = len({f.get("key") for f in i17})
    out["i17_top_keys"] = collections.Counter(f.get("key") for f in i17).most_common(8)
    ing = out["ingest"]
    sub = sum(v for kk, v in ing["unmapped_resources_by_type"].items() if kk.startswith("azure ") and kk.count("/") >= 2)
    out["coverage_top_level"] = {"mapped": ing["resources"], "distinct": ing["resources"] + ing["unmapped_resources"],
                                 "azure_child": sub,
                                 "pct": round(100 * ing["resources"] / (ing["resources"] + ing["unmapped_resources"] - sub), 1)}
    out["suggestions_I20"] = sorted({(f.get("key"), f.get("suggestion")) for f in rep["findings"] if f["rule"] == "I-20"})
    out["variants_I22"] = sorted({(f.get("used"), f.get("key")) for f in rep["findings"] if f["rule"] == "I-22"})
    out["conventions_I25"] = sorted({(f.get("used"), f.get("canonical")) for f in rep["findings"] if f["rule"] == "I-25"})
    # export-based checks on records without a closed-world verdict
    required = sorted({x for ks in ROLES.values() for x in ks})
    bp = baseline_pairs(rows, required, None)
    nov = {r["id"] for r in rows if r["in_scope"] and not r["complete"]}
    novrows = [r for r in rows if r["id"] in nov]
    out["export_checks"] = {
        "pairs_total": len(bp["exact"]),
        "pairs_on_no_verdict_records": sum(1 for p in bp["exact"] if p[0] in nov),
        "no_verdict_records": len(nov),
        "no_verdict_by_kind": dict(collections.Counter(r["kind"] for r in novrows).most_common(12)),
        "clo_pairs": sum(1 for f in rep["findings"] if f["rule"] in ("I-07", "I-22"))
                     + sum(len(f.get("missing") or []) for f in rep["findings"] if f["rule"] == "I-11"),
        "renames_clo_reports_as_missing_elsewhere": sum(1 for f in rep["findings"] if f["rule"] == "I-22"),
        "azure_case_insensitive_masks": len(bp["exact"] - bp["native_semantics"]),
    }
    if a.dl:
        paths = [a.inventory, orgp]
        ref = kb.entailments(kb.materialise("clo-r", paths)[0])
        out["engines"] = {"clo-r": len(ref)}
        for e in ("hermit", "pellet"):
            t = __import__("time").perf_counter()
            g, info = kb.materialise(e, paths, timeout=7200)
            E = kb.entailments(g) if g is not None else None
            out["engines"][e] = {"status": info.get("status"), "wall_s": round(__import__("time").perf_counter() - t, 1),
                                 "equal": E == ref if E is not None else None,
                                 "missing": len(ref - E) if E is not None else None,
                                 "extra": len(E - ref) if E is not None else None,
                                 "missing_examples": sorted(map(str, list(ref - E)[:4])) if E is not None else None}
    if a.keep_engines and os.path.exists(a.out):   # keep the (hours-long) DL comparison of a previous run
        old = json.load(open(a.out))
        if "engines" in old and "engines" not in out:
            out["engines"] = old["engines"]
            out["engines_note"] = "HermiT/Pellet comparison kept from the previous run (--keep-engines)"
    json.dump(out, open(a.out, "w"), indent=1, default=list)
    print(json.dumps({k: v for k, v in out.items() if k not in ("ingest", "ingest_noext")}, indent=1, default=list)[:6000])


if __name__ == "__main__":
    main()
