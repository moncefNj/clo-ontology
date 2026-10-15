#!/usr/bin/env python3
"""
e2e_scale.py -- RQ4': end-to-end cost of one cycle (materialisation + closed-world audit +
root causes + repair planning), not materialisation alone.

  python3 eval/e2e_scale.py --sizes 2000 4000 8000 16000 32000 --out results/rq4_e2e.json
"""
import argparse
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import gen_corpus  # noqa: E402
from tools import clo_audit  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[2000, 4000, 8000, 16000, 32000])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--budget", type=float, default=1800, help="stop growing once a run exceeds this (s)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    wd = tempfile.mkdtemp()
    rows = []
    for n in a.sizes:
        m = gen_corpus.build(n, a.seed)
        for r in m["resources"]:      # as in RQ4: no two-owner / two-type records
            r["types"] = r["types"][:1]
            r["owners"] = r["owners"][:1]
        ttl = os.path.join(wd, f"e2e{n}.ttl")
        open(ttl, "w").write(gen_corpus.to_ttl(m))
        t0 = time.perf_counter()
        rep, _ = clo_audit.run([ttl], os.path.join(wd, f"e2e{n}"))
        wall = time.perf_counter() - t0
        t = rep["timing"]
        rows.append({"n": n, "labels": sum(len(r["tags"]) for r in m["resources"]), "wall_s": round(wall, 2),
                     "materialise_s": round(t["materialise_s"], 2), "audit_s": round(t["audit_s"], 2),
                     "findings": len(rep["findings"])})
        print(rows[-1], flush=True)
        json.dump({"seed": a.seed, "rows": rows}, open(a.out, "w"), indent=1)
        if wall > a.budget:
            break


if __name__ == "__main__":
    main()
