#!/usr/bin/env python3
"""
validate_completeness.py -- RQ2': are the record-completeness rules of tools/ingest_c7n.py right?

The ingester decides, from the shape of each provider response, whether a record carries the
resource's whole tag set (rules A1, A2, A3, Z1, G1) or not (N). This script checks those
verdicts against the corpus itself: many resources are observed several times within one
recorded test ("flight"), through different operations (e.g. ec2.DescribeInstances and the
Resource Groups Tagging API, or s3.ListBuckets and s3.GetBucketTagging).

For every observation judged complete we look for a *witness*: another observation of the same
resource in the same flight, from a different response file, that carries a tag key the
"complete" observation lacks. A witness contradicts the verdict -- unless the test changed the
tags between the two calls (tag/untag actions are what many Custodian tests exercise), so the
contradiction rate is an upper bound on the error rate. Witnesses recorded *before* the judged
observation and witnesses recorded after it are counted separately.

For every observation judged N (no verdict) we count how often another observation in the same
flight shows that the resource does carry tags: there, closing the world would have reported
absent tags that the provider holds.

  python3 tools/validate_completeness.py --c7n ../cloud-custodian --out results/rq2_completeness.json
"""
import argparse
import collections
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ingest_c7n as I  # noqa: E402

COMPLETE_RULES = ("A1", "A2", "A3", "Z1", "G1")


def flight_of(o):
    return re.split(r"[/#]", o["src"])[0]


def order_of(o):
    """Position of the response within its flight (placebo files are numbered _1, _2, ...)."""
    m = re.search(r"_(\d+)\.json", o["src"]) or re.search(r"#(\d+)$", o["src"])
    return int(m.group(1)) if m else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--c7n", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    I.ARN_MAP.extend(I.ARN_EXT); I.AZURE_MAP.update(I.AZURE_EXT); I.GCP_MAP.update(I.GCP_EXT)
    inv = I.Inv()
    I.ingest_aws(os.path.join(a.c7n, "tests/data/placebo"), inv)
    I.ingest_azure(os.path.join(a.c7n, "tools/c7n_azure/tests_azure/cassettes"), inv)
    I.ingest_gcp(os.path.join(a.c7n, "tools/c7n_gcp/tests/data/flights"), inv)

    per_rule = collections.defaultdict(collections.Counter)
    examples = collections.defaultdict(list)
    pairs = collections.Counter()
    for (prov, kind, rid), obs in inv.obs.items():
        by_flight = collections.defaultdict(list)
        for o in obs:
            by_flight[flight_of(o)].append(o)
        for fl, os_ in by_flight.items():
            for o in os_:
                rule = o["rule"]
                c = per_rule[rule]
                c["observations"] += 1
                others = [x for x in os_ if x["src"] != o["src"]]
                if not others:
                    continue
                c["with_sibling"] += 1
                keys = set(o["tags"])
                if rule in COMPLETE_RULES:
                    wit = [x for x in others if set(x["tags"]) - keys]
                    if wit:
                        before = any(order_of(x) < order_of(o) for x in wit)
                        after = any(order_of(x) >= order_of(o) for x in wit)
                        c["contradicted"] += 1
                        c["contradicted_witness_before"] += before
                        c["contradicted_witness_after_only"] += after and not before
                        if len(examples[rule]) < 5:
                            examples[rule].append({"kind": kind, "flight": fl, "src": o["src"],
                                                   "witness": wit[0]["src"], "witness_rule": wit[0]["rule"],
                                                   "keys_missing": sorted(set(wit[0]["tags"]) - keys)[:5]})
                    for x in others:
                        pairs[(rule, x["rule"])] += 1
                else:  # N: no verdict
                    if any(x["tags"] for x in others):
                        c["sibling_shows_tags"] += 1
    rates = {}
    for rule, c in sorted(per_rule.items()):
        r = {**c}
        if rule in COMPLETE_RULES and c["with_sibling"]:
            r["contradiction_rate_upper_bound"] = round(c["contradicted"] / c["with_sibling"], 4)
            r["contradiction_rate_witness_before"] = round(c["contradicted_witness_before"] / c["with_sibling"], 4)
        if rule == "N" and c["with_sibling"]:
            r["withholding_necessary_rate"] = round(c["sibling_shows_tags"] / c["with_sibling"], 4)
        rates[rule] = r
    tot = collections.Counter()
    for rule in COMPLETE_RULES:
        tot.update({k: per_rule[rule][k] for k in ("with_sibling", "contradicted", "contradicted_witness_before")})
    out = {"per_rule": rates, "complete_rules_total": dict(tot),
           "complete_rules_contradiction_upper_bound": round(tot["contradicted"] / max(1, tot["with_sibling"]), 4),
           "complete_rules_contradiction_witness_before": round(tot["contradicted_witness_before"] / max(1, tot["with_sibling"]), 4),
           "examples": examples, "pairs": {f"{x}->{y}": n for (x, y), n in pairs.most_common(20)}}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(out, open(a.out, "w"), indent=1)
    print(json.dumps({k: v for k, v in out.items() if k != "examples"}, indent=1))


if __name__ == "__main__":
    main()
