#!/usr/bin/env python3
"""
test_v9.py -- checks of the v9 run-time pipeline.

  * CLO-R (rules/materialise.ru) and HermiT return the same operative entailment
    set E on the company example and on a synthetic estate;
  * the company example audit returns the documented root causes;
  * two owners give I-27 and do not merge teams; two types give I-28;
  * on a synthetic estate, every rule agrees with the independent oracle
    (precision = recall = 1) and no absence-based finding is raised on an
    incomplete record.

  python3 tests/test_v9.py        # exit code = number of failures
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "eval"))
from clo import kb  # noqa: E402
from tools import clo_audit  # noqa: E402
import eval_rules  # noqa: E402
import gen_corpus  # noqa: E402

failures = 0


def check(label, ok):
    global failures
    print(("PASS " if ok else "FAIL ") + label)
    failures += not ok


TMP = tempfile.mkdtemp()
COMPANY = os.path.join(ROOT, "examples", "company_example.ttl")

g1, _ = kb.materialise("clo-r", [COMPANY])
g2, info = kb.materialise("hermit", [COMPANY], timeout=900)
e1, e2 = kb.entailments(g1), kb.entailments(g2)
check(f"company example: CLO-R and HermiT entail the same set E ({len(e1)} triples)", e1 == e2)

m = gen_corpus.build(150, 7)
syn = os.path.join(TMP, "syn.ttl")
open(syn, "w").write(gen_corpus.to_ttl(m))
s1, _ = kb.materialise("clo-r", [syn])
s2, _ = kb.materialise("hermit", [syn], timeout=1800)
check("synthetic estate (150 resources, org module): CLO-R == HermiT on E",
      s2 is not None and kb.entailments(s1) == kb.entailments(s2))

rep, _ = clo_audit.run([COMPANY], os.path.join(TMP, "company"))
rc = rep["root_cause_counts"]
check("company example: 2 unlabelled, 3 renames, 11 missing keys, 1 unowned (root causes)",
      rc.get("I-11") == 2 and rc.get("I-22") == 3 and rc.get("I-07") == 11 and rc.get("I-26") == 1)
check("company example: raw I-07 count 19 folds to 11 root causes",
      rep["raw_counts"].get("I-07") == 19)
check("company example: data-classification is never filled in automatically",
      all(f.get("repair_value") is None for f in rep["findings"] if f.get("key") == "data-classification"))
check("company example: Payments' 'env' convention reported (I-25)",
      any(f["rule"] == "I-25" and f.get("team") == "Payments" and f.get("used") == "env" for f in rep["findings"]))
cov = {c["role"]: (c["covered"], c["governed"]) for c in rep["role_coverage"]}
check("company example: coverage denominators are the resources a role's policies govern",
      cov["Development"] == (1, 3) and cov["Platform engineering"] == (0, 0) and cov["FinOps"] == (3, 8))

two = os.path.join(TMP, "two.ttl")
open(two, "w").write("@prefix clo: <http://example.org/clo/ontology/clo#> .\n"
                     "clo:pay_vm clo:ownedBy clo:team_platform ; clo:hasResourceType clo:rt_gcp_instance .\n")
rep2, _ = clo_audit.run([COMPANY, two], os.path.join(TMP, "two"))
check("two owners -> I-27; two types -> I-28",
      rep2["root_cause_counts"].get("I-27") == 1 and rep2["root_cause_counts"].get("I-28") == 1)

r = eval_rules.evaluate(600, 11, workdir=TMP)
bad = {k: v for k, v in r["per_rule"].items() if v["fp"] or v["fn"]}
check(f"synthetic estate (600 resources): all {len(r['per_rule'])} rules agree with the oracle", not bad)
if bad:
    print(bad)
check("no absence-based finding on an incomplete record", r["withheld"]["absence_findings_on_incomplete"] == 0)

print(f"\n{failures} failure(s)")
sys.exit(failures)
