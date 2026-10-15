#!/usr/bin/env python3
"""
eval_repairs.py -- RQ5a: are the proposed repair values right, and are they safe?

For every missing-key finding (I-07) with an automatic value proposal, compare
the value with the resource's true value in the generator's model. Two policies:
  naive  v8 behaviour: the owning team's most frequent value, for every key
  safe   v9 behaviour: inherit from a partOf parent where the key allows it
         (clo:valueSource "inherit"), else the team's value if it dominates
         (>= 80 % of >= 2 uses) and the key allows it ("team-default"),
         else ask the owner; data-classification is never guessed.

  python3 eval/eval_repairs.py --n 2000 --seeds 1 2 3 4 5 --out results/rq5_repairs.json
"""
import argparse
import collections
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import gen_corpus  # noqa: E402
from tools import clo_audit  # noqa: E402


def run(n, seed, policy, wd):
    m = gen_corpus.build(n, seed)
    ttl = os.path.join(wd, f"rep{seed}.ttl")
    open(ttl, "w").write(gen_corpus.to_ttl(m))
    rep, _ = clo_audit.run([ttl], os.path.join(wd, f"rep{seed}_{policy}"), repair_policy=policy)
    true = {r["id"]: r["true"] for r in m["resources"]}
    c = collections.defaultdict(collections.Counter)
    for f in rep["findings"]:
        if f["rule"] != "I-07":
            continue
        k = f["key"]
        c[k]["findings"] += 1
        v = f.get("repair_value")
        if v is None:
            continue
        c[k]["proposed"] += 1
        c[k]["correct" if true[f["resource"]].get(k) == v else "wrong"] += 1
    return c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    wd = tempfile.mkdtemp()
    out = {}
    for pol in ("naive", "safe"):
        tot = collections.defaultdict(collections.Counter)
        for s in a.seeds:
            for k, v in run(a.n, s, pol, wd).items():
                tot[k].update(v)
        allc = collections.Counter()
        for v in tot.values():
            allc.update(v)
        out[pol] = {"per_key": {k: dict(v) for k, v in sorted(tot.items())}, "all": dict(allc)}
        print(pol, dict(allc))
        for k, v in sorted(tot.items()):
            print("   ", k, dict(v))
    json.dump(out, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
