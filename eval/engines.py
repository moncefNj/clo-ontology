#!/usr/bin/env python3
"""
engines.py -- RQ4: same entailments, at what cost?

For each estate size, generate an estate with the organisational module
(eval/gen_corpus.py), remove the records with two owners or two types (they are
equality conflicts a DL reasoner resolves by merging or by inconsistency; that
case is measured separately), and materialise the operative inference set E
with CLO-R, OWL RL (owlrl), HermiT and Pellet. Records wall time, the size of E
and whether each engine's E equals CLO-R's.

  python3 eval/engines.py --sizes 250 500 1000 2000 --dl-max 2000 --out results/rq4_engines.json
"""
import argparse
import copy
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import gen_corpus  # noqa: E402
from clo import kb  # noqa: E402


def estate(n, seed, clean=True):
    m = gen_corpus.build(n, seed)
    if clean:
        for r in m["resources"]:
            r["owners"] = r["owners"][:1]
            r["types"] = r["types"][:1]
    return m


def one(engine, path, timeout):
    t0 = time.perf_counter()
    g, info = kb.materialise(engine, [path], timeout=timeout)
    wall = time.perf_counter() - t0
    if g is None:
        return {"status": info.get("status"), "wall_s": round(wall, 2)}, None
    E = kb.entailments(g)
    return {"status": info.get("status", "ok"), "wall_s": round(wall, 3),
            "reason_s": round(info.get("reason_s", wall), 3), "E": len(E)}, E


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[250, 500, 1000, 2000, 4000, 8000, 16000, 32000])
    ap.add_argument("--dl-max", type=int, default=2000)
    ap.add_argument("--rl-max", type=int, default=4000)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", required=True)
    ap.add_argument("--no-conflicts", action="store_true", help="skip the equality-conflict run")
    a = ap.parse_args()
    wd = tempfile.mkdtemp()
    rows = []
    done = json.load(open(a.out))["rows"] if os.path.exists(a.out) else []
    for n in a.sizes:
        m = estate(n, a.seed)
        path = os.path.join(wd, f"e{n}.ttl")
        open(path, "w").write(gen_corpus.to_ttl(m))
        row = {"n": n, "labels": sum(len(r["tags"]) for r in m["resources"]), "triples_abox": None}
        ref = None
        times = []
        for i in range(a.repeats):
            res, E = one("clo-r", path, None)
            times.append(res["wall_s"])
            ref = E
        row["clo-r"] = {"wall_s": times, "E": len(ref)}
        engines = []
        if n <= a.rl_max:
            engines.append("owlrl")
        if n <= a.dl_max:
            engines += ["hermit", "pellet"]
        for e in engines:
            res, E = one(e, path, a.timeout)
            if E is not None:
                res["equal_to_clo_r"] = E == ref
                res["missing_vs_clo_r"] = len(ref - E)
                res["extra_vs_clo_r"] = len(E - ref)
                res["missing_examples"] = sorted(map(str, list(ref - E)[:3]))
            row[e] = res
            print(n, e, res.get("status"), res.get("wall_s"), res.get("equal_to_clo_r"), flush=True)
        print(n, "clo-r", times, len(ref), flush=True)
        rows.append(row)
        json.dump({"rows": done + rows, "seed": a.seed}, open(a.out, "w"), indent=1)
    if a.no_conflicts:
        return
    # equality conflicts: the same estate with its two-owner / two-type records kept
    m = estate(min(a.sizes), a.seed, clean=False)
    path = os.path.join(wd, "conflicts.ttl")
    open(path, "w").write(gen_corpus.to_ttl(m))
    conf = {"two_types": sum(len(r["types"]) > 1 for r in m["resources"]),
            "two_owners": sum(len(r["owners"]) > 1 for r in m["resources"])}
    for e in ("clo-r", "hermit"):
        res, E = one(e, path, a.timeout)
        conf[e] = res
    json.dump({"rows": done + rows, "seed": a.seed, "conflicts": conf}, open(a.out, "w"), indent=1)
    print("conflicts", conf)


if __name__ == "__main__":
    main()
