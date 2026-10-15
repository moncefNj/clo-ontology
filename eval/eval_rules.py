#!/usr/bin/env python3
"""
eval_rules.py -- RQ1: are CLO's findings correct?

For each seed: generate an estate (eval/gen_corpus.py), run the CLO cycle
(tools/clo_audit.py), derive the expected root-cause findings with the
independent oracle (eval/oracle.py), and report per-rule precision and recall,
the detection of each planted defect kind, and the absence-based findings
correctly withheld on incomplete records.

  python3 eval/eval_rules.py --n 2000 --seeds 1 2 3 4 5 --out results/rq1.json
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
import oracle as O  # noqa: E402
from tools import clo_audit  # noqa: E402

FAMILY = {  # kept for reference: the rule family of each defect kind
    "redundant": {"I-22r"}, "missing": {"I-07", "I-22", "I-11"}, "unlabelled": {"I-11"}, "variant": {"I-22", "I-22r"},
          "convention": {"I-22", "I-22r"}, "vocab": {"I-09"}, "case": {"I-13"}, "long": {"I-14"},
          "foreign_prefix": {"I-15"}, "conflict": {"I-16"}, "unmanaged": {"I-17", "I-20", "I-13"},
          "typo_key": {"I-20"}, "no_owner": {"I-26"}, "two_owners": {"I-27"}, "two_types": {"I-28"}}
ABSENCE = {"I-07", "I-11", "I-22", "I-26"}


def by_rule(T):
    d = collections.defaultdict(set)
    for t in T:
        d[t[0]].add(t)
    return d


def evaluate(n, seed, engine="clo-r", workdir=None, single_type=False):
    m = gen_corpus.build(n, seed)
    if single_type:   # two-type records make a DL reasoner merge types or fail (see eval/conflicts.py)
        for r in m["resources"]:
            r["types"] = r["types"][:1]
        m["planted"] = [p for p in m["planted"] if p["defect"] != "two_types"]
    wd = workdir or tempfile.mkdtemp()
    ttl = os.path.join(wd, f"s{seed}.ttl")
    open(ttl, "w").write(gen_corpus.to_ttl(m))
    json.dump(m, open(os.path.join(wd, f"s{seed}.json"), "w"))
    rep, _ = clo_audit.run([ttl], os.path.join(wd, f"out{seed}_{engine}"), engine=engine)
    got = O.clo_tuples(rep)
    exp = O.Oracle(m).findings()
    G, X = by_rule(got), by_rule(exp)
    per_rule = {}
    for r in sorted(set(G) | set(X)):
        tp = len(G[r] & X[r])
        per_rule[r] = {"expected": len(X[r]), "reported": len(G[r]), "tp": tp,
                       "fp": len(G[r] - X[r]), "fn": len(X[r] - G[r]),
                       "fp_examples": sorted(map(str, G[r] - X[r]))[:3], "fn_examples": sorted(map(str, X[r] - G[r]))[:3]}
    # planted defects, matched to CLO's findings by (resource, key) -- without the oracle.
    # A planted defect is "detected" if CLO reports the finding that names that resource and key
    # (team-level conventions: the team and the spelling). Misses are classified by facts of the
    # generator's model; only the "key not required here" reason uses the specification (the
    # oracle's policy reach), and it is reported separately.
    o = O.Oracle(m)
    res = {r["id"]: r for r in m["resources"]}
    team_name = {t["id"]: t["name"] for t in m["teams"]}
    got_by = collections.defaultdict(set)
    for t in got:
        got_by[t[0]].add(t[1:])
    has = lambda rule, *x: x in got_by[rule]
    i11 = {t[0]: set(t[1]) for t in got_by["I-11"]}

    def detected(p):
        d, rid, k, used = p["defect"], p["resource"], p.get("key"), p.get("used")
        r = res[rid]
        if d == "missing":
            return has("I-07", rid, k) or has("I-22", rid, k) or k in i11.get(rid, ())
        if d == "unlabelled":
            return rid in i11
        if d in ("variant", "convention"):
            if has("I-22", rid, k) or has("I-22r", rid, k, used):
                return True
            return "team" if any(has("I-25", team_name[t], used, k) for t in r["owners"]) else False
        if d == "redundant":
            return has("I-22r", rid, k, used)
        if d == "vocab":
            return any(t[0] == rid and t[1] == "environment" for t in got_by["I-09"])
        if d == "case":
            return has("I-13", rid, k)
        if d == "long":
            return has("I-14", rid, k, "key")
        if d == "foreign_prefix":
            return any(t[0] == rid and t[1] == k for t in got_by["I-15"])
        if d == "conflict":
            return any(t[0] == rid for t in got_by["I-16"])
        if d == "unmanaged":
            return has("I-17", rid, k) or any(t[0] == rid and t[1] == k for t in got_by["I-20"]) or has("I-13", rid, k)
        if d == "typo_key":
            return any(t[0] == rid and t[1] == used for t in got_by["I-20"])
        if d == "no_owner":
            return has("I-26", rid)
        if d == "two_owners":
            return has("I-27", rid)
        if d == "two_types":
            return has("I-28", rid)
        return False

    ABS_KINDS = {"missing", "unlabelled", "no_owner", "variant", "convention"}

    def why_not(p):
        d, rid, k, used = p["defect"], p["resource"], p.get("key"), p.get("used")
        r = res[rid]
        spelled = used if d in ("variant", "convention", "redundant", "typo_key") else k
        if d in ("variant", "convention", "redundant") and o.variant_of(used) is None:
            return "spelling outside the declared synonym groups (reported as I-17/I-20)"
        if d in ("missing", "unlabelled", "no_owner", "variant", "convention") and not r["complete"]:
            return "record incomplete (withheld, R4)"
        if not o.scope(r) and d in ABS_KINDS:
            return "type not in audit scope"
        if spelled and d not in ("missing",) and spelled not in r["tags"] and d not in ("no_owner", "two_owners", "two_types",
                                                                                    "conflict", "unlabelled"):
            return "overwritten by a later defect or truncated listing"
        if d == "redundant" and k not in r["tags"]:
            return "overwritten by a later defect or truncated listing"
        if d == "missing" and k in r["tags"]:
            return "overwritten by a later defect"
        if d == "unlabelled" and r["tags"]:
            return "overwritten by a later defect"
        if d == "no_owner" and r["owners"]:
            return "overwritten by a later defect"
        if d in ("missing", "variant", "convention") and k not in o.required(rid):
            return "key not required on this resource (spec)"
        if d == "conflict" and not (r["tags"].get("environment") == "prod" and r["tags"].get("data-classification") == "public"):
            return "overwritten by a later defect"
        if d == "unmanaged" and o.variant_of(k):
            return "key is a variant of a managed key (reported as such)"
        return "unexplained"

    planted = collections.defaultdict(lambda: {"planted": 0, "detected": 0, "detected_team_level": 0,
                                               "missed": collections.Counter()})
    withheld = {"incomplete": 0, "absence_findings_on_incomplete": 0}
    rules_on = collections.defaultdict(set)
    for t in got:
        rules_on[t[1]].add(t[0])
    for p in m["planted"]:
        d, rid = p["defect"], p["resource"]
        if d == "incomplete":
            withheld["incomplete"] += 1
            withheld["absence_findings_on_incomplete"] += len(rules_on[rid] & ABSENCE)
            continue
        planted[d]["planted"] += 1
        hit = detected(p)
        if hit is True:
            planted[d]["detected"] += 1
        elif hit == "team":
            planted[d]["detected_team_level"] += 1
        else:
            planted[d]["missed"][why_not(p)] += 1
    planted = {d: {**v, "missed": dict(v["missed"])} for d, v in planted.items()}
    return {"seed": seed, "n": n, "engine": engine, "resources": len(m["resources"]),
            "labels": sum(len(r["tags"]) for r in m["resources"]), "teams": len(m["teams"]),
            "per_rule": per_rule, "planted": dict(planted), "withheld": withheld,
            "raw_counts": rep["raw_counts"], "root_cause_counts": rep["root_cause_counts"], "timing": rep["timing"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    ap.add_argument("--engine", default="clo-r")
    ap.add_argument("--out", required=True)
    ap.add_argument("--workdir")
    ap.add_argument("--single-type", action="store_true", help="drop the second type of two-type records")
    a = ap.parse_args()
    runs = [evaluate(a.n, s, a.engine, a.workdir, a.single_type) for s in a.seeds]
    tot = collections.defaultdict(lambda: collections.Counter())
    for r in runs:
        for rule, v in r["per_rule"].items():
            tot[rule].update({k: v[k] for k in ("expected", "reported", "tp", "fp", "fn")})
    summary = {}
    for rule, c in sorted(tot.items()):
        p = c["tp"] / c["reported"] if c["reported"] else 1.0
        rc = c["tp"] / c["expected"] if c["expected"] else 1.0
        summary[rule] = {**c, "precision": round(p, 4), "recall": round(rc, 4)}
    json.dump({"summary": summary, "runs": runs}, open(a.out, "w"), indent=1)
    for rule, v in summary.items():
        print(f"{rule:6} exp={v['expected']:6} rep={v['reported']:6} P={v['precision']:.3f} R={v['recall']:.3f}")
    for r in runs:
        print(r["seed"], {d: f"{v['detected']}+{v['detected_team_level']}t of {v['planted']} {v['missed']}"
                          for d, v in r["planted"].items()}, r["withheld"])


if __name__ == "__main__":
    main()
