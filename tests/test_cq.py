#!/usr/bin/env python3
"""Competency questions (examples/cq/CQ*.rq) on the company example: expected answers."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import run_cqs  # noqa: E402
from clo import kb  # noqa: E402

fails = 0


def check(name, ok):
    global fails
    print(("PASS " if ok else "FAIL ") + name)
    fails += not ok


A = {cid: rows for cid, _, rows in run_cqs.answers([os.path.join(kb.ROOT, "examples", "company_example.ttl")])}
check("CQ1: pay-receipts needs 5 keys, app for Development via the Payments team standard",
      len(A["CQ1"]) == 5 and {"key": "app", "role": "Development", "policy": "Payments team standard",
                              "resource": "pay-receipts"} in A["CQ1"])
check("CQ2: i-pay-01 (AWS) has the same kind as vm-build (Azure)",
      any(r["other"] == "vm-build" and r["kind"] == "InstanceKind" for r in A["CQ2"]))
check("CQ3: team Payments uses env for environment", {"team": "Payments", "used": "env", "canonical": "environment"} in A["CQ3"])
v = {r["resource"]: r["verdict"] for r in A["CQ4"]}
check("CQ4: vol-scratch in scope without verdict; admins out of scope",
      v["vol-scratch"].startswith("in scope, no verdict") and v["admins"] == "out of audit scope")
check("CQ5: data-classification has no value source", {"key": "data-classification", "sources": "none: ask the owner"} in A["CQ5"])
cov = {r["role"]: (int(r["governed"]), int(r["covered"])) for r in A["CQ6"]}
check("CQ6: coverage equals the audit's (FinOps 3/8, Development 1/3)", cov["FinOps"] == (8, 3) and cov["Development"] == (3, 1))
print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
