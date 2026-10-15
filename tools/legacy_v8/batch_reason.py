#!/usr/bin/env python3
"""
batch_reason.py -- run HermiT over a CLO A-Box in independent batches.

Why: the shared individuals of an inventory (categories, providers, label
keys and values, accounts, policies) connect every resource to every other,
so a single HermiT realisation of the whole A-Box grows super-linearly with
its size. The DL inferences of CLO are local to a
resource's neighbourhood: its type, kind, category and provider, its labels,
its account and organisational chain, and its partOf ancestors. Reasoning
over each partOf-connected component together with all shared individuals
therefore yields the same entailments, in time linear in the number of
batches.

What is lost: anything that relates resources across batches. In CLO that is
owl:hasKey (two records of the same resource in different batches are not
merged) and the inconsistencies such a merge would reveal. Deduplicate by key
before batching.

Usage:
  python3 tools/batch_reason.py --tbox ontology/clo_ontology_v8.ttl --abox abox.nt \
      --batch 100 --out inferred.tsv
  python3 tools/batch_reason.py ... --whole      # single run, for comparison

Output: one line per resource: resource IRI, inferred classes, inferred
governedBy policies (sorted), and total wall-clock time on stderr.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import defaultdict

CLO = "http://example.org/clo/ontology/clo#"
RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"


def parse_nt(path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            s, rest = line.split(" ", 1)
            p, o = rest.split(" ", 1)
            yield s, p, o.rstrip(" .")


def components(triples):
    """Resources, each resource's own triples, partOf components, shared rest."""
    resources = {s for s, p, o in triples if p == f"<{RDF_TYPE}>" and o == f"<{CLO}CloudResource>"}
    labels_of = defaultdict(set)
    for s, p, o in triples:
        if s in resources and p == f"<{CLO}hasLabel>":
            labels_of[s].add(o)
    owner = {lb: r for r, lbs in labels_of.items() for lb in lbs}
    parent = {r: r for r in resources}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for s, p, o in triples:
        if p == f"<{CLO}partOf>" and s in resources and o in resources:
            parent[find(s)] = find(o)
    own, shared = defaultdict(list), []
    for t in triples:
        s = t[0]
        r = s if s in resources else owner.get(s)
        (own[find(r)] if r else shared).append(t)
    comps = defaultdict(list)
    for r in resources:
        comps[find(r)].append(r)
    return list(comps.values()), own, shared, find


def run_batch(tbox_nt, abox_nt):
    code = r'''
import owlready2 as ow, json, sys
w = ow.World()
w.get_ontology("file://" + sys.argv[1]).load()
a = w.get_ontology("file://" + sys.argv[2]).load()
with a:
    ow.sync_reasoner_hermit(w, infer_property_values=True, debug=0)
CR = w.search_one(iri="%sCloudResource")
out = {}
for r in CR.instances(world=w):
    out[r.iri] = [sorted(c.iri for c in r.is_a if hasattr(c, "iri")),
                  sorted(p.iri for p in getattr(r, "governedBy", []))]
print(json.dumps(out))
''' % CLO
    p = subprocess.run([sys.executable, "-I", "-c", code, tbox_nt, abox_nt],
                       capture_output=True, text=True)
    if p.returncode:
        sys.exit(p.stderr[-2000:])
    return json.loads(p.stdout.strip().splitlines()[-1])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tbox", required=True)
    ap.add_argument("--abox", required=True)
    ap.add_argument("--batch", type=int, default=100)
    ap.add_argument("--whole", action="store_true")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    import rdflib
    with tempfile.TemporaryDirectory() as td:
        tbox_nt = os.path.join(td, "tbox.nt")
        g = rdflib.Graph(); g.parse(a.tbox); g.serialize(tbox_nt, format="nt", encoding="utf-8")
        triples = list(parse_nt(a.abox))
        t0 = time.perf_counter()
        if a.whole:
            batches = [triples]
        else:
            comps, own, shared, find = components(triples)
            comps.sort(key=len, reverse=True)
            batches, cur, size = [], [], 0
            for c in comps:
                if size and size + len(c) > a.batch:
                    batches.append(cur); cur, size = [], 0
                cur += own[find(c[0])]; size += len(c)
            if cur:
                batches.append(cur)
            batches = [shared + b for b in batches]
        result = {}
        for i, b in enumerate(batches):
            path = os.path.join(td, f"b{i}.nt")
            with open(path, "w") as f:
                f.write(f"<http://example.org/clo/ontology/clo-batch-{i}> <{RDF_TYPE}> <http://www.w3.org/2002/07/owl#Ontology> .\n")
                for s, p, o in b:
                    f.write(f"{s} {p} {o} .\n")
            result.update(run_batch(tbox_nt, path))
        wall = time.perf_counter() - t0
    with open(a.out, "w") as f:
        for r in sorted(result):
            f.write(f"{r}\t{' '.join(result[r][0])}\t{' '.join(result[r][1])}\n")
    print(f"{len(batches)} batch(es), {len(result)} resources, {wall:.1f} s", file=sys.stderr)


if __name__ == "__main__":
    main()
