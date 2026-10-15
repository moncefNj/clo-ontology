#!/usr/bin/env python3
"""
run_cqs.py -- answer CLO's competency questions (examples/cq/CQ*.rq) on an inventory.

The T-Box, the catalogue and the organisational module are loaded with the inventory, the
open-world inferences are materialised with CLO-R (rules/materialise.ru), and each question is
one SPARQL query over the result. Writes a Markdown report (default: examples/cq/answers.md).

  python3 tools/run_cqs.py                                   # the company example
  python3 tools/run_cqs.py --abox data/open/c7n_inventory.ttl --out /tmp/cq.md
"""
import argparse
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from clo import audit as A  # noqa: E402
from clo import kb  # noqa: E402

CQ_DIR = os.path.join(kb.ROOT, "examples", "cq")


def answers(aboxes):
    st, _ = kb.run_clo_r(aboxes)
    out = []
    for f in sorted(glob.glob(os.path.join(CQ_DIR, "CQ*.rq"))):
        text = open(f).read()
        question = next((l[1:].strip() for l in text.splitlines() if l.startswith("#")), os.path.basename(f))
        rows = list(A._q(st, text))
        out.append((os.path.basename(f)[:-3], question, rows))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--abox", nargs="+", default=[os.path.join(kb.ROOT, "examples", "company_example.ttl")])
    ap.add_argument("--out", default=os.path.join(CQ_DIR, "answers.md"))
    a = ap.parse_args()
    L = ["# Competency questions, answered on " + ", ".join(os.path.basename(p) for p in a.abox), ""]
    for cid, q, rows in answers(a.abox):
        L += [f"## {q}", ""]
        if not rows:
            L += ["(no answer)", ""]
            continue
        cols = list(rows[0])
        L += ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
        L += ["| " + " | ".join(str(r[c] if r[c] is not None else "") for c in cols) + " |" for r in rows]
        L.append("")
        print(f"{cid}: {len(rows)} row(s)")
    open(a.out, "w").write("\n".join(L) + "\n")
    print("wrote", a.out)


if __name__ == "__main__":
    main()
