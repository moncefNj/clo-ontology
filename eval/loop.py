#!/usr/bin/env python3
"""
loop.py -- RQ5b: the closed loop over successive snapshots (simulation).

Each cycle runs Monitor -> Analyse -> Plan with CLO on the current snapshot,
then simulates Execute by the owning teams:
  * a proposed value (inherit / account default / team default) or a rename is
    accepted with probability ACCEPT;
  * a request to the owner (ask-owner, unlabelled resource, missing owner) is
    answered with the true value with probability ANSWER;
  * a record without a closed-world verdict is re-read completely with
    probability REREAD (the monitor fetches its tags);
and the estate drifts: DRIFT new resources per cycle arrive with their team's
spelling conventions; at cycle NEW_ROLE_AT the company adds a governance role
(Sustainability needs carbon-scope) to the shared standard.

Per cycle it records open error-level findings (root causes), resources that
carry every key their policies require, and silent errors: tag values written by
an accepted repair that differ from the true value (closed findings, wrong data).

  python3 eval/loop.py --n 2000 --cycles 8 --seeds 1 2 3 --out results/rq5_loop.json
"""
import argparse
import collections
import copy
import hashlib
import json
import os
import random
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import gen_corpus  # noqa: E402
import oracle as O  # noqa: E402
from clo import audit as A  # noqa: E402
from tools import clo_audit  # noqa: E402

ACCEPT, ANSWER, REREAD, DRIFT, NEW_ROLE_AT = 0.9, 0.5, 0.7, 0.03, 4


def scope_of(account):
    """The true carbon scope of an account. 9.0 used Python's hash(), which is salted per process
    (PYTHONHASHSEED), so the loop was not reproducible run to run; this is stable."""
    return "scope-" + str(int(hashlib.sha256(account.encode()).hexdigest(), 16) % 3)


def add_role(m):
    m["roles"]["Sustainability"] = ["carbon-scope"]
    gen_corpus.ROLE_IRI["Sustainability"] = "SustainabilityRole"
    m["policies"][0]["serves"].append("Sustainability")
    for r in m["resources"]:
        r["true"]["carbon-scope"] = scope_of(r["account"])


def drift(m, rnd, cycle, seed):
    """New resources from the same generator, with their team's conventions; ids made unique."""
    extra = gen_corpus.build(max(10, int(len(m["resources"]) * DRIFT)), seed * 100 + cycle)
    team_conv = {t["id"]: t["convention"] for t in m["teams"]}
    for r in extra["resources"]:
        r["id"] = f"c{cycle}_{r['id']}"
        if r["parent"]:
            r["parent"] = f"c{cycle}_{r['parent']}"
        r["owners"] = [rnd.choice(m["teams"])["id"]] if r["owners"] else []
        r["account"] = rnd.choice([a["id"] for a in m["accounts"] if a["provider"] == r["provider"]])
        if "carbon-scope" in {k for ks in m["roles"].values() for k in ks}:
            r["true"]["carbon-scope"] = scope_of(r["account"])
        for k, v in team_conv.get(r["owners"][0] if r["owners"] else None, {}).items():
            if k in r["tags"]:
                r["tags"][v] = r["tags"].pop(k)
        r["provider_tags"] = dict(r["tags"])
    m["resources"].extend(extra["resources"])


def compliant(m):
    o = O.Oracle(m)
    inscope = [r for r in m["resources"] if o.scope(r)]
    ok = sum(1 for r in inscope if o.required(r["id"]) <= set(r["provider_tags"]))
    right = sum(1 for r in inscope if all(r["provider_tags"].get(k) == r["true"].get(k, r["provider_tags"].get(k))
                                          and k in r["provider_tags"] for k in o.required(r["id"])))
    return ok, len(inscope), right


def run(n, cycles, seed, policy, wd):
    rnd = random.Random(seed)
    m = gen_corpus.build(n, seed)
    byid = lambda: {r["id"]: r for r in m["resources"]}
    silent = 0
    hist = []
    for c in range(cycles):
        if c == NEW_ROLE_AT:
            add_role(m)
        ttl = os.path.join(wd, f"loop{seed}_{policy}_{c}.ttl")
        open(ttl, "w").write(gen_corpus.to_ttl(m))
        rep, _ = clo_audit.run([ttl], os.path.join(wd, f"loop{seed}_{policy}_{c}"), repair_policy=policy)
        errs = [f for f in rep["findings"] if f["severity"] == "error"]
        ok, tot, right = compliant(m)
        R = byid()
        wrong_now = sum(1 for r in m["resources"] for k, v in r["provider_tags"].items()
                        if k in r["true"] and r["true"][k] != v and r.get("_written", {}).get(k))
        hist.append({"cycle": c, "resources": len(m["resources"]), "open_errors": len(errs),
                     "by_rule": dict(collections.Counter(f["rule"] for f in errs)),
                     "compliant": ok, "correct": right, "in_scope": tot, "silent_wrong_values": wrong_now,
                     "no_verdict": len(rep["no_verdict"])})
        # Execute (simulated)
        for f in errs:
            r = R.get(f["resource"])
            if r is None:
                continue
            rule, k = f["rule"], f.get("key")
            if rule == "I-22" and rnd.random() < ACCEPT:
                used = f.get("used")
                if used in r["tags"]:
                    r["tags"][k] = r["tags"].pop(used)
            elif rule == "I-07" and f.get("repair_value") is not None and rnd.random() < ACCEPT:
                r["tags"][k] = f["repair_value"]
                r.setdefault("_written", {})[k] = True
            elif rule == "I-07" and f.get("repair_value") is None and r["owners"] and rnd.random() < ANSWER:
                if k in r["true"]:
                    r["tags"][k] = r["true"][k]
            elif rule == "I-11" and r["owners"] and rnd.random() < ANSWER:
                for kk in f.get("missing") or []:
                    if kk in r["true"]:
                        r["tags"][kk] = r["true"][kk]
            elif rule in ("I-26", "I-27") and rnd.random() < ANSWER:
                r["owners"] = [rnd.choice(m["teams"])["id"]]
            elif rule == "I-09" and rnd.random() < ANSWER and k in r["true"]:
                r["tags"][k] = r["true"][k]
        for r in m["resources"]:
            if not r["complete"] and rnd.random() < REREAD:
                r["complete"] = True
                r["tags"] = {**r["provider_tags"], **r["tags"]}
            r["provider_tags"] = dict(r["tags"]) if r["complete"] else {**r["provider_tags"], **r["tags"]}
        drift(m, rnd, c, seed)
    return hist


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--cycles", type=int, default=8)
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    wd = tempfile.mkdtemp()
    out = {"params": {"accept": ACCEPT, "answer": ANSWER, "reread": REREAD, "drift": DRIFT, "new_role_at": NEW_ROLE_AT},
           "runs": {}}
    for pol in ("safe", "naive"):
        out["runs"][pol] = [run(a.n, a.cycles, s, pol, wd) for s in a.seeds]
        for c in range(a.cycles):
            xs = [h[c] for h in out["runs"][pol]]
            print(pol, c, "errors", [x["open_errors"] for x in xs], "compliant",
                  [f"{x['compliant']}/{x['in_scope']}" for x in xs], "correct", [x["correct"] for x in xs],
                  "silent", [x["silent_wrong_values"] for x in xs])
    json.dump(out, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
