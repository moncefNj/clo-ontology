#!/usr/bin/env python3
"""
run_baselines.py -- RQ3: CLO against existing solutions on the same estates.

Systems (what each one reads is part of its definition):
  CLO        inventory export (tags + recordComplete), full organisational semantics
  CLO-noLC   ablation: CLO with the local closed world switched off (every record complete)
  NATIVE     AWS Config managed rule required-tags (case-sensitive) and Azure Policy
             built-in "Require a tag on resources" (tag names case-insensitive), assigned at
             organisation / OU / account scope; resource-type scoped variants for category
             policies; nothing for GCP, Kubernetes or DigitalOcean. Reads provider-side tags.
  OPA-idiom  Rego, data-driven required keys per scope, exact key, over the inventory export
  OPA-team   OPA-idiom extended with team scope and every type of a record (rego/idiomatic_team.rego)
  NATIVE+    NATIVE plus Google Cloud organisation-policy custom constraints on resource.labels for
             Compute instances and disks and Cloud Storage buckets. Custom constraints are preventive
             (create/update; existing resources only in dry run), so treating them as a detective check
             of the whole snapshot is a best case for this baseline.
  OPA-full   Rego re-implementing CLO's I-07/I-11/I-22/I-26 semantics (baselines/rego/full.rego)
  CUSTODIAN  Cloud Custodian policies (one per resource type and scope), evaluated with
             c7n's own ValueFilter on c7n-shaped records of provider-side tags; no
             DigitalOcean provider; team scope not expressible.

Ground truth (two, because the requirement itself is part of what is compared):
  full   every (resource, key) pair where the company standard -- all policies with CLO's reach,
         including team policies and composition -- requires the key and the provider-side tag
         set lacks it under its canonical spelling, for resources whose type supports tags;
  flat   the same with the requirement every tool can state: organisation, OU, account and
         category policies only (no team policies, no inheritance through composition).
Recall against "full" therefore measures expressiveness as much as detection; recall against
"flat" isolates detection.

  python3 baselines/run_baselines.py --n 2000 --seeds 1 2 3 4 5 --out results/rq3.json
"""
import argparse
import collections
import copy
import difflib
import json
import os
import subprocess
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "eval"))
import gen_corpus  # noqa: E402
import oracle as O  # noqa: E402
from tools import clo_audit  # noqa: E402

C7N = {"aws_autoscaling_group": "aws.asg", "aws_ec2_instance": "aws.ec2", "aws_ec2_volume": "aws.ebs",
       "aws_s3_bucket": "aws.s3", "aws_rds_instance": "aws.rds", "aws_vpc": "aws.vpc", "aws_ec2_subnet": "aws.subnet",
       "aws_lambda_function": "aws.lambda", "azure_compute_virtual_machine": "azure.vm", "azure_compute_disk": "azure.disk",
       "azure_sql_server_database": "azure.sqldatabase", "azure_network_virtual_network": "azure.vnet",
       "gcp_instance": "gcp.instance", "gcp_disk": "gcp.disk", "gcp_bucket": "gcp.bucket",
       "gcp_sql_database_instance": "gcp.sql-instance", "kubernetes_node": "k8s.node",
       "kubernetes_service": "k8s.service", "kubernetes_persistent_volume": "k8s.volume",
       "aws_dynamodb_table": "aws.dynamodb-table"}
NOTIFY = {"aws": {"type": "notify", "to": ["resource-owner"], "template": "default",
                  "transport": {"type": "sqs", "queue": "https://sqs.us-east-1.amazonaws.com/123456789012/c7n"}},
          "azure": {"type": "notify", "to": ["resource-owner"], "template": "default",
                    "transport": {"type": "asq", "queue": "https://example.queue.core.windows.net/c7n"}},
          "gcp": {"type": "notify", "to": ["resource-owner"], "template": "default",
                  "transport": {"type": "pubsub", "topic": "projects/example/topics/c7n"}},
          "k8s": {"type": "label", "labels": {"c7n-missing-tags": "true"}}}


# ── configuration a practitioner would derive from the organisation ─────────────
def config(m):
    acct_ou = {a["id"]: a["ou"] for a in m["accounts"]}
    keys = lambda p: sorted(set(p["requires"]) | {k for ro in p["serves"] for k in m["roles"][ro]})
    cfg = {"shared": [], "ou": {}, "account": {}, "by_type": {}, "team": {},
           "taggable_types": sorted(t for t, c in m["catalogue"].items() if c["support"] in ("full", "partial")),
           "synonyms": m["synonyms"], "reserved": [p for v in O.RESERVED.values() for p in v]}
    for p in m["policies"]:
        kind, tgt = p["attach"]
        if kind == "ou" and tgt == "ou_root":
            cfg["shared"] = sorted(set(cfg["shared"]) | set(keys(p)))
        elif kind == "ou":
            cfg["ou"][tgt] = sorted(set(cfg["ou"].get(tgt, [])) | set(keys(p)))
        elif kind == "account":
            cfg["account"][tgt] = sorted(set(cfg["account"].get(tgt, [])) | set(keys(p)))
        elif kind == "team":
            cfg["team"][tgt] = sorted(set(cfg["team"].get(tgt, [])) | set(keys(p)))
        elif kind == "category":
            types = sorted(t for t, c in m["catalogue"].items() if c["category"] == tgt)
            for k in keys(p):
                cfg["by_type"][k] = sorted(set(cfg["by_type"].get(k, [])) | set(types))
    cfg["managed"] = sorted(set(cfg["shared"]) | {k for v in cfg["ou"].values() for k in v}
                            | {k for v in cfg["account"].values() for k in v} | set(cfg["by_type"])
                            | {k for v in cfg["team"].values() for k in v} | {k for ks in m["roles"].values() for k in ks}
                            | set(m["synonyms"]))
    return cfg, acct_ou


def export(m, acct_ou, view="inventory"):
    return {"resources": [{"id": r["id"], "type": r["type"], "types": r["types"], "provider": r["provider"],
                           "account": r["account"],
                           "ou": acct_ou[r["account"]], "owners": r["owners"], "parent": r["parent"],
                           "complete": r["complete"] if view == "inventory" else True,
                           "tags": r["tags"] if view == "inventory" else r["provider_tags"]} for r in m["resources"]]}


# ── ground truth ────────────────────────────────────────────────────────────────
def truth_flat(m):
    mm = copy.deepcopy(m)
    mm["policies"] = [p for p in mm["policies"] if p["attach"][0] != "team"]
    for r in mm["resources"]:
        r["tags"], r["complete"], r["parent"] = r["provider_tags"], True, None
    o = O.Oracle(mm)
    return {(r["id"], k) for r in mm["resources"] if o.scope(r) for k in o.required(r["id"]) if k not in r["tags"]}


def truth(m):
    mm = copy.deepcopy(m)
    for r in mm["resources"]:
        r["tags"], r["complete"] = r["provider_tags"], True
    o = O.Oracle(mm)
    T = set()
    for r in mm["resources"]:
        if o.scope(r):
            for k in o.required(r["id"]):
                if k not in r["tags"]:
                    T.add((r["id"], k))
    return T


def clo_pairs(rep):
    P = set()
    for f in rep["findings"]:
        if f["rule"] in ("I-07", "I-22"):
            P.add((f["resource"], f["key"]))
        elif f["rule"] == "I-11":
            P |= {(f["resource"], k) for k in f.get("missing") or []}
    return P


# ── B1 provider-native ──────────────────────────────────────────────────────────
# AWS Config REQUIRED_TAGS evaluates 30 resource types (AWS Config Developer Guide, required-tags);
# these are the catalogue kinds among them. Lambda functions, for instance, are not evaluated.
AWS_CONFIG_TYPES = {"aws_acm_certificate", "aws_autoscaling_group", "aws_cloudformation_stack", "aws_dynamodb_table",
                    "aws_ec2_instance", "aws_ec2_internet_gateway", "aws_ec2_network_acl", "aws_ec2_network_interface",
                    "aws_ec2_route_table", "aws_ec2_security_group", "aws_ec2_subnet", "aws_ec2_volume", "aws_vpc",
                    "aws_elb", "aws_alb", "aws_rds_instance", "aws_rds_snapshot", "aws_s3_bucket"}


def native(m, cfg, acct_ou):
    P = set()
    for r in m["resources"]:
        if r["type"] not in cfg["taggable_types"] or r["provider"] not in ("AWS", "Azure"):
            continue
        if r["provider"] == "AWS" and r["type"] not in AWS_CONFIG_TYPES:
            continue
        req = set(cfg["shared"]) | set(cfg["ou"].get(acct_ou[r["account"]], [])) | set(cfg["account"].get(r["account"], []))
        req |= {k for k, ts in cfg["by_type"].items() if r["type"] in ts}
        tags = r["provider_tags"]
        have = set(tags) if r["provider"] == "AWS" else {k.lower() for k in tags}
        for k in req:
            if (k if r["provider"] == "AWS" else k.lower()) not in have:
                P.add((r["id"], k))
    return P


# Google Cloud custom constraints on resource.labels: Compute Engine (Instance, Disk, ...) and
# Cloud Storage buckets support label conditions (Compute Engine and Cloud Storage
# custom-constraint documentation). Labels are case-sensitive and lower-case only.
GCP_CUSTOM_TYPES = {"gcp_instance", "gcp_disk", "gcp_bucket"}


def native_plus(m, cfg, acct_ou):
    P = native(m, cfg, acct_ou)
    for r in m["resources"]:
        if r["provider"] != "GCP" or r["type"] not in GCP_CUSTOM_TYPES or r["type"] not in cfg["taggable_types"]:
            continue
        req = set(cfg["shared"]) | set(cfg["ou"].get(acct_ou[r["account"]], [])) | set(cfg["account"].get(r["account"], []))
        req |= {k for k, ts in cfg["by_type"].items() if r["type"] in ts}
        P |= {(r["id"], k) for k in req if k not in r["provider_tags"]}
    return P


def native_artefacts(m, cfg):
    """The same artefacts tools/clo_compile.py emits (clo/native.py), for this configuration."""
    from clo import native as NV
    aws, az = [], []
    scopes = [("organization", "root", cfg["shared"], None)] \
        + [("ou", o, ks, None) for o, ks in sorted(cfg["ou"].items())] \
        + [("account", a, ks, None) for a, ks in sorted(cfg["account"].items())] \
        + [("organization", "root", [k], ts) for k, ts in sorted(cfg["by_type"].items())]
    for i, (kind, sid, ks, types) in enumerate(scopes):
        aws_t = [t for t in (types or []) if t.startswith("aws_")]
        az_t = [t for t in (types or []) if t.startswith("azure_")]
        if types is None or aws_t:
            aws += NV.aws_rules(f"clo-{i}", kind, sid, ks, aws_t or None)
        if types is None or az_t:
            az += NV.azure_items(f"clo-{i}", "account" if kind == "account" else "mg", sid, ks, az_t or None)
    return {"aws_config.json": json.dumps(aws, indent=1), "azure_policy.json": json.dumps(az, indent=1)}


# ── B2 OPA / Rego ───────────────────────────────────────────────────────────────
_REGO_CHILD = r'''
import json, sys
from regopy import Interpreter
mod, data, inp, which, out = sys.argv[1:6]
it = Interpreter()
it.add_module(which, open(mod).read())
it.add_data(json.load(open(data)))
it.set_input(json.load(open(inp)))
res = json.loads(str(it.query("data.tagging." + which + ".violation")))
json.dump(res["expressions"][0], open(out, "w"))
'''


def rego(cfg, inventory, which):
    """Evaluate a Rego policy with rego-cpp (regopy), in a child process: the interpreter's
    memory is released after each evaluation."""
    with tempfile.TemporaryDirectory() as td:
        d, i, o = (os.path.join(td, x) for x in ("data.json", "input.json", "out.json"))
        json.dump({"cfg": cfg}, open(d, "w"))
        json.dump(inventory, open(i, "w"))
        subprocess.run([sys.executable, "-I", "-c", _REGO_CHILD, os.path.join(HERE, "rego", which + ".rego"),
                        d, i, which, o], check=True)
        return {tuple(p) for p in json.load(open(o))}


def rego_artefacts(cfg, which):
    drop = {"full": (), "idiomatic_team": ("synonyms", "reserved", "managed")}.get(
        which, ("team", "synonyms", "reserved", "managed"))
    data = {"cfg": {k: v for k, v in cfg.items() if k not in drop}}
    return {f"{which}.rego": open(os.path.join(HERE, "rego", which + ".rego")).read(),
            "data.json": json.dumps(data, indent=1, sort_keys=True)}


# ── B3 Cloud Custodian ──────────────────────────────────────────────────────────
def custodian_policies(cfg, acct_ou):
    pols = []
    scopes = [("all", cfg["shared"])] + [(f"ou:{o}", ks) for o, ks in sorted(cfg["ou"].items())] \
        + [(f"account:{a}", ks) for a, ks in sorted(cfg["account"].items())]
    for t, res in sorted(C7N.items()):
        if t not in cfg["taggable_types"]:
            continue
        for scope, ks in scopes:
            extra = [k for k, ts in cfg["by_type"].items() if t in ts] if scope == "all" else []
            keys = sorted(set(ks) | set(extra))
            if not keys:
                continue
            pols.append({"name": f"required-tags-{res.replace('.', '-')}-{scope.replace(':', '-').replace('_', '-')}",
                         "resource": res, "comment": f"scope {scope} (c7n-org account tag selector)",
                         "filters": [{"or": [{tag_key(res, k): "absent"} for k in keys]}],
                         "actions": [NOTIFY[res.split(".")[0]]]})
    return pols


def tag_key(res, k):
    if res.startswith("gcp."):
        return f'labels."{k}"'
    if res.startswith("k8s."):
        return f'metadata.labels."{k}"'
    return f"tag:{k}"


def c7n_record(r):
    t = r["provider_tags"]
    if r["provider"] == "AWS":
        return {"Tags": [{"Key": k, "Value": v} for k, v in t.items()]}
    if r["provider"] == "Azure":
        return {"tags": dict(t)}
    if r["provider"] == "GCP":
        return {"labels": dict(t)}
    return {"metadata": {"labels": dict(t)}}


def custodian(m, cfg, acct_ou, pols):
    from c7n.filters.core import ValueFilter
    filt = {}
    P = set()
    for r in m["resources"]:
        res = C7N.get(r["type"])
        if not res:
            continue
        rec = c7n_record(r)
        for p in pols:
            if p["resource"] != res:
                continue
            scope = p["comment"].split()[1]
            if scope.startswith("ou:") and acct_ou[r["account"]] != scope[3:]:
                continue
            if scope.startswith("account:") and r["account"] != scope[8:]:
                continue
            for cond in p["filters"][0]["or"]:
                (key, val), = cond.items()
                f = filt.get(key)
                if f is None:
                    f = filt[key] = ValueFilter({key: val}).validate()
                if f(rec):
                    P.add((r["id"], key.split(":", 1)[1] if key.startswith("tag:") else key.split('"')[1]))
    return P


def custodian_validate(pols, wd):
    by_provider = collections.defaultdict(list)
    for p in pols:
        by_provider[p["resource"].split(".")[0]].append(p)
    ok = {}
    for prov, ps in by_provider.items():
        path = os.path.join(wd, f"c7n_{prov}.yml")
        yaml.safe_dump({"policies": ps}, open(path, "w"), sort_keys=False)
        import shutil
        exe = shutil.which("custodian") or os.path.join(os.path.dirname(sys.executable), "custodian")
        p = subprocess.run([exe, "validate", path], capture_output=True, text=True)
        ok[prov] = {"policies": len(ps), "valid": p.returncode == 0, "msg": (p.stdout + p.stderr).strip()[-300:]}
    return ok


def fn_causes(P, T, m, cfg, acct_ou, covered=lambda r: True):
    """Why a system missed a true (resource, key) pair: the first applicable cause."""
    res = {r["id"]: r for r in m["resources"]}
    mm = copy.deepcopy(m)
    for r in mm["resources"]:
        r["tags"], r["complete"] = r["provider_tags"], True
    o = O.Oracle(mm)
    team_keys = lambda r: {k for t in r["owners"] for k in cfg["team"].get(t, [])}
    own = lambda r: (set(cfg["shared"]) | set(cfg["ou"].get(acct_ou[r["account"]], []))
                     | set(cfg["account"].get(r["account"], []))
                     | {k for k, ts in cfg["by_type"].items() if any(t in ts for t in r["types"])})
    c = collections.Counter()
    for rid, k in T - P:
        r = res[rid]
        if len(set(r["types"])) > 1:
            c["two-type record"] += 1
        elif not covered(r):
            c[f"provider/type not covered ({r['provider']})"] += 1
        elif k not in own(r) | team_keys(r):
            c["inherited from a parent"] += 1
        elif k not in own(r):
            c["team policy"] += 1
        elif any(x != k and x.lower() == k.lower() for x in r["provider_tags"]):
            c["case variant"] += 1
        else:
            c["other"] += 1
    return dict(c.most_common())


def scores(P, T, m, TF=None):
    incomplete = {r["id"] for r in m["resources"] if not r["complete"]}
    flat = {}
    if TF is not None:   # recall against the flat requirement (detection only)
        flat = {"recall_flat": round(len(P & TF) / len(TF), 4) if TF else 1.0, "tp_flat": len(P & TF),
                "truth_flat": len(TF)}
    tp = len(P & T)
    Tc = {x for x in T if x[0] not in incomplete}
    return {"reported": len(P), "tp": tp, "fp": len(P - T), "fn": len(T - P),
            "precision": round(tp / len(P), 4) if P else 1.0, "recall": round(tp / len(T), 4) if T else 1.0,
            "recall_complete_records": round(len(P & Tc) / len(Tc), 4) if Tc else 1.0,
            "fp_on_incomplete": len({x for x in P - T if x[0] in incomplete}), **flat}


def provider_view(m):
    """Setting A: every system reads the provider-side tag sets, all records complete."""
    mm = copy.deepcopy(m)
    for r in mm["resources"]:
        r["tags"], r["complete"] = dict(r["provider_tags"]), True
    return mm


def run_seed(n, seed, wd):
    m = gen_corpus.build(n, seed)
    cfg, acct_ou = config(m)
    T = truth(m)
    TF = truth_flat(m)
    out = {}
    sc = lambda P: scores(P, T, m, TF)
    # Setting A -- same provider-side data for every system
    ma = provider_view(m)
    ttla = os.path.join(wd, f"b{seed}_A.ttl")
    open(ttla, "w").write(gen_corpus.to_ttl(ma))
    repa, _ = clo_audit.run([ttla], os.path.join(wd, f"b{seed}_A"))
    out["A:CLO"] = sc(clo_pairs(repa))
    Pn = native(m, cfg, acct_ou)
    out["A:NATIVE"] = sc(Pn)
    out["A:NATIVE"]["fn_causes"] = fn_causes(Pn, T, m, cfg, acct_ou, lambda r: r["provider"] == "Azure" or (
        r["provider"] == "AWS" and r["type"] in AWS_CONFIG_TYPES))
    pols = custodian_policies(cfg, acct_ou)
    Pc = custodian(m, cfg, acct_ou, pols)
    out["A:CUSTODIAN"] = sc(Pc)
    out["A:CUSTODIAN"]["fn_causes"] = fn_causes(Pc, T, m, cfg, acct_ou, lambda r: r["type"] in C7N)
    inva = export(ma, acct_ou)
    Pi = rego(cfg, inva, "idiomatic")
    out["A:OPA-idiom"] = sc(Pi)
    out["A:OPA-idiom"]["fn_causes"] = fn_causes(Pi, T, m, cfg, acct_ou)
    Pt = rego(cfg, inva, "idiomatic_team")
    out["A:OPA-team"] = sc(Pt)
    out["A:OPA-team"]["fn_causes"] = fn_causes(Pt, T, m, cfg, acct_ou)
    Pnp = native_plus(m, cfg, acct_ou)
    out["A:NATIVE+"] = sc(Pnp)
    out["A:NATIVE+"]["fn_causes"] = fn_causes(Pnp, T, m, cfg, acct_ou, lambda r: r["provider"] == "Azure" or (
        r["provider"] == "AWS" and r["type"] in AWS_CONFIG_TYPES) or r["type"] in GCP_CUSTOM_TYPES)
    out["A:OPA-full"] = sc(rego(cfg, inva, "full"))
    # Setting B -- an inventory export in which some records are incomplete
    ttl = os.path.join(wd, f"b{seed}.ttl")
    open(ttl, "w").write(gen_corpus.to_ttl(m))
    rep, _ = clo_audit.run([ttl], os.path.join(wd, f"b{seed}_clo"))
    out["B:CLO"] = sc(clo_pairs(rep))
    m2 = copy.deepcopy(m)
    for r in m2["resources"]:
        r["complete"] = True
    ttl2 = os.path.join(wd, f"b{seed}_nolc.ttl")
    open(ttl2, "w").write(gen_corpus.to_ttl(m2))
    rep2, _ = clo_audit.run([ttl2], os.path.join(wd, f"b{seed}_nolc"))
    out["B:CLO-noLC"] = sc(clo_pairs(rep2))
    inv = export(m, acct_ou)
    out["B:OPA-idiom"] = sc(rego(cfg, inv, "idiomatic"))
    out["B:OPA-team"] = sc(rego(cfg, inv, "idiomatic_team"))
    full = rego(cfg, inv, "full")
    out["B:OPA-full"] = sc(full)
    out["B:OPA-full"]["identical_to_CLO"] = full == clo_pairs(rep)
    out["_truth"] = len(T)
    out["_truth_flat"] = len(TF)
    out["_truth_on_incomplete"] = sum(1 for x in T if not next(r for r in m["resources"] if r["id"] == x[0])["complete"])
    return out, m, cfg, acct_ou, pols


# ── artefact size and change effort ─────────────────────────────────────────────
def clo_artefact(m):
    """The organisational part of the CLO A-Box: roles' needs, policies, synonyms, vocabularies."""
    mm = copy.deepcopy(m)
    mm["resources"] = []
    lines = gen_corpus.to_ttl(mm).splitlines()
    # declarations of the organisation itself (accounts, OUs, teams) are shared by every system and not
    # counted; the lines that attach a policy to one of them are part of the standard and are counted
    keep = lambda l: not (l.startswith(("clo:acct_", "clo:team_", "clo:ou_")) and "governedBy" not in l)
    return {"org.ttl": "\n".join(l for l in lines if keep(l))}


def artefacts(m):
    cfg, acct_ou = config(m)
    a = {}
    a["CLO"] = clo_artefact(m)
    a["NATIVE"] = native_artefacts(m, cfg)
    a["OPA-idiom"] = rego_artefacts(cfg, "idiomatic_team")
    a["OPA-full"] = rego_artefacts(cfg, "full")
    a["CUSTODIAN"] = {"policies.yml": yaml.safe_dump({"policies": custodian_policies(cfg, acct_ou)}, sort_keys=False)}
    return a, cfg


def size(files):
    return sum(len([l for l in t.splitlines() if l.strip()]) for t in files.values())


def diff(a, b):
    n = 0
    for f in set(a) | set(b):
        for l in difflib.unified_diff(a.get(f, "").splitlines(), b.get(f, "").splitlines(), lineterm="", n=0):
            if (l.startswith("+") or l.startswith("-")) and not l.startswith(("+++", "---")):
                n += 1
    return n


def scenarios(m):
    """Five changes an organisation makes; edits each artefact set needs (None: not expressible)."""
    base, cfg0 = artefacts(m)
    res = {}

    def apply(name, fn, expressible):
        mm = copy.deepcopy(m)
        fn(mm)
        new, _ = artefacts(mm)
        res[name] = {sys_: (diff(base[sys_], new[sys_]) if expressible.get(sys_, True) else None) for sys_ in base}

    def s1(mm):
        mm["roles"]["Sustainability"] = ["carbon-scope"]
        gen_corpus.ROLE_IRI["Sustainability"] = "SustainabilityRole"
        mm["policies"][0]["serves"].append("Sustainability")
    apply("S1 new role, served by the shared standard", s1, {})

    def s2(mm):
        mm["roles"]["Security"] = mm["roles"]["Security"] + ["data-owner"]
    apply("S2 a role needs one more key", s2, {})

    def s3(mm):
        mm["synonyms"]["environment"] = mm["synonyms"]["environment"] + ["tier"]
    apply("S3 accept a new synonym spelling", s3, {"NATIVE": False, "OPA-idiom": False, "CUSTODIAN": False})

    def s4(mm):
        mm["catalogue"]["aws_dynamodb_table"] = {"basekind": "DatabaseKind", "category": "Database", "support": "full"}
    apply("S4 a new resource type in a governed category", s4, {})

    def s5(mm):
        mm["policies"].append({"id": "pol_team1", "label": "Team 1 standard", "serves": ["Development"],
                               "requires": [], "attach": ("team", mm["teams"][1]["id"])})
    apply("S5 a team-level policy", s5, {"NATIVE": False, "CUSTODIAN": False})
    return {"size_lines": {k: size(v) for k, v in base.items()}, "scenarios": res}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    wd = tempfile.mkdtemp()
    runs = []
    for s in a.seeds:
        out, m, cfg, acct_ou, pols = run_seed(a.n, s, wd)
        runs.append(out)
        print(s, json.dumps({k: (v if k.startswith("_") else {x: v[x] for x in ("precision", "recall", "fp", "fn")})
                             for k, v in out.items()}))
    agg = {}
    for sysname in [k for k in runs[0] if not k.startswith("_")]:
        tot = collections.Counter()
        for r in runs:
            tot.update({k: r[sysname][k] for k in ("reported", "tp", "fp", "fn", "fp_on_incomplete", "tp_flat", "truth_flat")})
        tot_t = sum(r["_truth"] for r in runs)
        fc = collections.Counter()
        for r in runs:
            fc.update(r[sysname].get("fn_causes", {}))
        agg[sysname] = {**tot, "fn_causes": dict(fc.most_common()), "precision": round(tot["tp"] / tot["reported"], 4) if tot["reported"] else 1.0,
                        "recall": round(tot["tp"] / tot_t, 4),
                        "recall_flat": round(tot["tp_flat"] / tot["truth_flat"], 4) if tot["truth_flat"] else None}
    effort = scenarios(gen_corpus.build(a.n, a.seeds[0]))
    m = gen_corpus.build(a.n, a.seeds[0])
    cfg, acct_ou = config(m)
    val = custodian_validate(custodian_policies(cfg, acct_ou), wd)
    json.dump({"aggregate": agg, "runs": runs, "effort": effort, "custodian_validate": val}, open(a.out, "w"), indent=1)
    print(json.dumps(agg, indent=1))
    print(json.dumps(effort, indent=1))
    print(json.dumps({k: {x: v[x] for x in ("policies", "valid")} for k, v in val.items()}))


if __name__ == "__main__":
    main()
