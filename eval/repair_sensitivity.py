#!/usr/bin/env python3
"""
repair_sensitivity.py -- RQ5a': how much of the repair accuracy comes from the generator?

The released estates obey three regularities that the value sources exploit: a child shares
its parent's context, the environment is the account's, the cost centre is the team's.
This sweep breaks each regularity with probability v (gen_corpus.build(..., violate=v)) and
measures, for every missing-key finding (I-07), the share of keys for which a value is
proposed (coverage) and the share of proposals equal to the true value (accuracy), for
three policies:
  naive     the owning team's most frequent value for every key (8.x behaviour)
  majority  a practitioner's heuristic without CLO's metadata: inherit from a parent for
            every key, the account's most frequent value for the environment, the team's
            most frequent value otherwise; no threshold
  safe      CLO's policy: value sources per key, dominance threshold, never guess a key
            without a value source (data-classification)

  python3 eval/repair_sensitivity.py --n 2000 --seeds 1 2 3 --levels 0 0.1 0.25 0.5 \
      --out results/rq5_sensitivity.json
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

POLICIES = ("naive", "majority", "safe")


def run(n, seed, v, wd):
    m = gen_corpus.build(n, seed, violate=v)
    ttl = os.path.join(wd, f"sens{seed}_{v}.ttl")
    open(ttl, "w").write(gen_corpus.to_ttl(m))
    true = {r["id"]: r["true"] for r in m["resources"]}
    out = {}
    for pol in POLICIES:
        rep, _ = clo_audit.run([ttl], os.path.join(wd, f"sens{seed}_{v}_{pol}"), repair_policy=pol)
        c = collections.Counter()
        dc = collections.Counter()
        for f in rep["findings"]:
            if f["rule"] != "I-07":
                continue
            c["findings"] += 1
            val = f.get("repair_value")
            if val is None:
                continue
            ok = true[f["resource"]].get(f["key"]) == val
            c["proposed"] += 1
            c["correct" if ok else "wrong"] += 1
            if f["key"] == "data-classification":
                dc["proposed"] += 1
                dc["wrong"] += not ok
        out[pol] = {**c, "dc_proposed": dc["proposed"], "dc_wrong": dc["wrong"]}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    ap.add_argument("--levels", type=float, nargs="+", default=[0.0, 0.1, 0.25, 0.5])
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    wd = tempfile.mkdtemp()
    res = {"levels": a.levels, "seeds": a.seeds, "n": a.n, "rows": []}
    for v in a.levels:
        tot = {p: collections.Counter() for p in POLICIES}
        for s in a.seeds:
            for p, c in run(a.n, s, v, wd).items():
                tot[p].update(c)
        row = {"violate": v}
        for p, c in tot.items():
            row[p] = {**c, "coverage": round(c["proposed"] / max(1, c["findings"]), 4),
                      "accuracy": round(c["correct"] / max(1, c["proposed"]), 4)}
        res["rows"].append(row)
        print(v, {p: (row[p]["coverage"], row[p]["accuracy"], row[p]["wrong"]) for p in POLICIES}, flush=True)
    json.dump(res, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
