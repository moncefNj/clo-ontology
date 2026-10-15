#!/usr/bin/env python3
"""
conflicts.py -- RQ4b: what equality does to a DL reasoner's answers.

On the company example, add one record with two resource types (an AWS and a
GCP instance type; hasResourceType is functional in the T-Box), then one with two
types of different categories, and compare HermiT's operative entailments with
CLO-R's. CLO-R derives no equality and reports the records as I-28.

  python3 eval/conflicts.py --out results/rq4_conflicts.json
"""
import argparse
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from clo import kb  # noqa: E402

CASES = {
    "two types, same category": "clo:pay_vm clo:hasResourceType clo:rt_gcp_instance .",
    "two types, different categories": "clo:pay_vm clo:hasResourceType clo:rt_aws_s3_bucket .",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    company = os.path.join(kb.ROOT, "examples", "company_example.ttl")
    out = {}
    for name, triple in CASES.items():
        p = os.path.join(tempfile.mkdtemp(), "c.ttl")
        open(p, "w").write("@prefix clo: <http://example.org/clo/ontology/clo#> .\n" + triple + "\n")
        ref = kb.entailments(kb.materialise("clo-r", [company, p])[0])
        g, info = kb.materialise("hermit", [company, p], timeout=1800)
        res = {"clo_r_E": len(ref), "hermit_status": info.get("status")}
        if g is not None and info.get("status") == "ok":
            E = kb.entailments(g)
            extra = sorted(E - ref)
            res.update({"hermit_E": len(E), "extra": len(extra), "missing": len(ref - E),
                        "extra_resources": len({s for s, _, _ in extra}),
                        "extra_examples": [" ".join(x.split("#")[-1] for x in t) for t in extra[:6]]})
        out[name] = res
        print(name, res)
    json.dump({"conflicts": out}, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
