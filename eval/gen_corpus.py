#!/usr/bin/env python3
"""
gen_corpus.py -- synthetic multi-cloud estates with a known ground truth.

The generator builds a company (organisational units, accounts on five
providers, teams, governance roles, policies at five attachment points),
assigns every resource its true tag values, then plants defects of every kind
the rules address. It writes

  <out>.json   the model: organisation, policies, vocabularies, resources with
               their observed and true tags, and the list of planted defects;
  <out>.ttl    the same estate as a CLO A-Box.

The expected findings are not written by the generator: eval/oracle.py
derives them from <out>.json with an independent implementation of the rule
semantics (no RDF, no SPARQL, no reasoner), and eval/eval_rules.py compares
CLO's output with them and with the planted defects.

  python3 eval/gen_corpus.py --n 2000 --seed 1 --out results/corpus/s1
"""
import argparse
import json
import os
import random
import sys

import rdflib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLO = "http://example.org/clo/ontology/clo#"

ROLES = {"FinOps": ["cost-center"], "Security": ["data-classification"],
         "Operations": ["owner", "environment"], "Development": ["app"], "Platform engineering": ["managed-by"]}
ROLE_IRI = {"FinOps": "FinOpsRole", "Security": "SecurityRole", "Operations": "OperationsRole",
            "Development": "DeveloperRole", "Platform engineering": "PlatformRole"}
SYNONYMS = {"environment": ["env", "stage"], "cost-center": ["costcentre"], "owner": ["contact"]}
VARIANTS = {"environment": ["env", "Environment", "Env", "stage"], "cost-center": ["CostCenter", "cost_center", "costcentre"],
            "owner": ["Owner", "contact"], "app": ["App", "application"]}   # spellings teams may adopt
VOCAB = {"environment": ["prod", "staging", "dev"], "data-classification": ["public", "internal", "confidential", "restricted"]}
TYPO = {"prod": "prd", "staging": "stagin", "dev": "deev"}
CONFLICTS = [("environment", "prod", "data-classification", "public")]
VALUE_SOURCE = {"cost-center": ["inherit", "team-default"], "environment": ["inherit", "account-default"], "owner": ["inherit"],
                "app": ["inherit", "team-default"], "managed-by": ["team-default"]}
UNMANAGED = ["Name", "project", "tmp", "build-id", "Project"]
TYPO_KEYS = {"environment": "enviroment", "cost-center": "cost-centr", "owner": "ownr"}
PROVIDERS = {  # provider: (lowercaseOnly, keyMax, valueMax, reserved prefixes)
    "AWS": (False, 128, 256, ["aws:"]), "Azure": (False, 512, 256, ["microsoft", "azure", "windows"]),
    "GCP": (True, 63, 63, ["goog-", "google-"]), "Kubernetes": (False, 63, 63, ["kubernetes.io/", "k8s.io/"]),
    "DigitalOcean": (False, None, None, [])}   # no ProviderConstraint declared in the T-Box
# (type, provider, parent type or None, weight)
TYPES = [
    ("aws_autoscaling_group", "AWS", None, 2), ("aws_ec2_instance", "AWS", "aws_autoscaling_group", 6),
    ("aws_ec2_volume", "AWS", "aws_ec2_instance", 5), ("aws_s3_bucket", "AWS", None, 3),
    ("aws_rds_instance", "AWS", None, 2), ("aws_vpc", "AWS", None, 1), ("aws_ec2_subnet", "AWS", "aws_vpc", 2),
    ("aws_lambda_function", "AWS", None, 2), ("aws_iam_group", "AWS", None, 1), ("aws_root_user", "AWS", None, 0.3),
    ("azure_compute_virtual_machine", "Azure", None, 4), ("azure_compute_disk", "Azure", "azure_compute_virtual_machine", 4),
    ("azure_sql_server_database", "Azure", None, 2), ("azure_network_virtual_network", "Azure", None, 1),
    ("azure_network_subnet", "Azure", "azure_network_virtual_network", 1),
    ("gcp_instance", "GCP", None, 4), ("gcp_disk", "GCP", "gcp_instance", 3), ("gcp_bucket", "GCP", None, 2),
    ("gcp_sql_database_instance", "GCP", None, 1), ("gcp_network", "GCP", None, 1), ("gcp_firewall", "GCP", None, 1),
    ("kubernetes_node", "Kubernetes", None, 2), ("kubernetes_service", "Kubernetes", None, 2),
    ("kubernetes_persistent_volume", "Kubernetes", None, 1),
    ("digitalocean_droplet", "DigitalOcean", None, 1), ("digitalocean_volume", "DigitalOcean", "digitalocean_droplet", 1),
]
# defect rates (per resource, applied in this order)
RATES = {"redundant": 0.02, "missing": 0.25, "unlabelled": 0.05, "variant": 0.06, "vocab": 0.04, "case": 0.04, "long": 0.01,
         "foreign_prefix": 0.01, "conflict": 0.02, "unmanaged": 0.15, "typo_key": 0.02, "no_owner": 0.03,
         "two_owners": 0.01, "two_types": 0.005, "incomplete": 0.08, "convention_team_share": 0.4}


def catalogue():
    g = rdflib.Graph()
    for f in ("clo_ontology_v8.ttl", "clo_types.ttl"):
        g.parse(os.path.join(ROOT, "ontology", f))
    C = rdflib.Namespace(CLO)
    info = {}
    for t in g.subjects(rdflib.RDF.type, C.ResourceType):
        name = str(g.value(t, C.resourceTypeName))
        bk = g.value(t, C.implementsBaseKind)
        cat = g.value(bk, C.categoryOf) if bk else None
        sup = g.value(t, C.labelingSupport)
        info[name] = {"basekind": bk.split("#")[1] if bk else None, "category": cat.split("#")[1] if cat else None,
                      "support": str(sup) if sup else "unknown"}
    return info


def build(n, seed, violate=0.0):
    """violate: probability that a resource departs from each of the three regularities the
    repair policies rely on (a child shares its parent's context; the environment is the
    account's; the cost centre is the team's). Drawn from a separate random stream, so
    violate=0 reproduces the released estates exactly."""
    rnd = random.Random(seed)
    rv = random.Random(seed * 7919 + 17)
    cat = catalogue()
    m = {"seed": seed, "providers": {p: {"lowercaseOnly": a, "keyMax": b, "valueMax": c, "reserved": d}
                                     for p, (a, b, c, d) in PROVIDERS.items()},
         "roles": ROLES, "synonyms": SYNONYMS, "vocab": VOCAB, "conflicts": CONFLICTS, "value_source": VALUE_SOURCE,
         "catalogue": {t: cat[t] for t, *_ in TYPES}}
    # organisation: root -> 3 OUs -> one account per provider (and per environment for AWS/Azure/GCP)
    ous = [{"id": "ou_root", "parent": None}] + [{"id": f"ou_{x}", "parent": "ou_root"} for x in ("retail", "corporate", "data")]
    m["ous"] = ous
    accounts = []
    for ou in ous[1:]:
        for p in PROVIDERS:
            envs = ["prod", "staging", "dev"] if p in ("AWS", "Azure", "GCP") else ["prod"]
            for e in envs:
                accounts.append({"id": f"acct_{p.lower()}_{ou['id'][3:]}_{e}", "provider": p, "ou": ou["id"], "env": e})
    m["accounts"] = accounts
    teams = []
    for i in range(max(4, n // 120)):
        ou = ous[1 + i % 3]["id"]
        conv = {}
        if rnd.random() < RATES["convention_team_share"]:
            k = rnd.choice(list(VARIANTS))
            conv[k] = rnd.choice(VARIANTS[k])
        teams.append({"id": f"team_{i}", "name": f"Team {i}", "ou": ou, "cost_center": f"CC-{1000 + i}",
                      "owner": f"t{i}-lead", "apps": [f"app-{i}-{j}" for j in range(rnd.randint(1, 3))],
                      "managed_by": rnd.choice(["terraform", "helm", "pulumi"]), "convention": conv})
    m["teams"] = teams
    # policies at every attachment point
    pols = [{"id": "pol_shared", "label": "Shared standard", "serves": ["FinOps", "Security", "Operations"],
             "requires": [], "attach": ("ou", "ou_root")},
            {"id": "pol_retail", "label": "Retail OU standard", "serves": ["Development"], "requires": [],
             "attach": ("ou", "ou_retail")},
            {"id": "pol_db", "label": "Database category policy", "serves": [], "requires": ["backup-tier"],
             "attach": ("category", "Database")},
            {"id": "pol_platform", "label": "Platform team standard", "serves": ["Platform engineering"],
             "requires": [], "attach": ("team", teams[0]["id"])},
            {"id": "pol_acct", "label": "Account policy", "serves": ["Development"], "requires": [],
             "attach": ("account", accounts[0]["id"])}]
    m["policies"] = pols
    m["key_vocab_extra"] = {"backup-tier": None}
    # resources
    res, by_id = [], {}
    weights = [w for *_, w in TYPES]
    while len(res) < n:
        t, prov, ptype, _ = rnd.choices(TYPES, weights)[0]
        team = rnd.choice(teams)
        acct = rnd.choice([a for a in accounts if a["provider"] == prov and a["ou"] == team["ou"]])
        app = rnd.choice(team["apps"])
        parent = None
        if ptype:
            cands = [r for r in res if r["type"] == ptype and r["account"] == acct["id"]]
            if cands and rnd.random() < 0.85:
                parent = rnd.choice(cands)
        rid = f"r{len(res)}"
        true = {"cost-center": team["cost_center"], "environment": acct["env"], "owner": team["owner"],
                "app": app, "data-classification": rnd.choice(VOCAB["data-classification"]),
                "managed-by": team["managed_by"]}
        if parent:  # composition: a child shares its parent's application context
            keep_own = violate and rv.random() < violate      # ... unless it does not
            for k in ("cost-center", "environment", "owner", "app"):
                if not keep_own:
                    true[k] = parent["true"][k]
            if rnd.random() < 0.7:
                true["data-classification"] = parent["true"]["data-classification"]
        if violate and rv.random() < violate:                 # an account that mixes environments
            true["environment"] = rv.choice(["prod", "staging", "dev"])
        if violate and rv.random() < violate:                 # a team with several cost centres
            true["cost-center"] = f"{team['cost_center']}-{rv.randint(1, 3)}"
        if cat[t]["category"] == "Database":
            true["backup-tier"] = rnd.choice(["gold", "silver"])
        r = {"id": rid, "type": t, "provider": prov, "account": acct["id"], "owners": [team["id"]],
             "parent": parent["id"] if parent else None, "complete": True, "types": [t], "true": true,
             "support": cat[t]["support"]}
        support = cat[t]["support"]
        r["tags"] = {} if support in ("none",) else dict(true)
        if support == "unknown" and rnd.random() < 0.5:
            r["tags"] = {}
        # keys a policy cannot require (not governed) are still carried: realistic over-tagging
        res.append(r)
        by_id[rid] = r
    planted = []
    plant = lambda d, r, **kw: planted.append({"defect": d, "resource": r["id"], **kw})
    for r in res:
        if not r["tags"]:
            continue
        team = next(t for t in teams if t["id"] == r["owners"][0])
        # team convention (I-22/I-25): the team writes its own spelling
        for k, v in team["convention"].items():
            if k in r["tags"] and rnd.random() < 0.9:
                r["tags"][v] = r["tags"].pop(k)
                plant("convention", r, key=k, used=v)
        if rnd.random() < RATES["unlabelled"]:
            r["tags"] = {}
            plant("unlabelled", r)
            continue
        if rnd.random() < RATES["missing"]:
            ks = [k for k in r["tags"] if k in ROLES_KEYS]
            if ks:
                k = rnd.choice(ks)
                del r["tags"][k]
                plant("missing", r, key=k)
        if rnd.random() < RATES["variant"]:
            ks = [k for k in r["tags"] if k in VARIANTS]
            if ks:
                k = rnd.choice(ks)
                v = rnd.choice(VARIANTS[k])
                r["tags"][v] = r["tags"].pop(k)
                plant("variant", r, key=k, used=v)
        if rnd.random() < RATES["redundant"]:
            ks = [k for k in r["tags"] if k in VARIANTS]
            if ks:
                k = rnd.choice(ks)
                v = rnd.choice(VARIANTS[k])
                r["tags"][v] = r["tags"][k]
                plant("redundant", r, key=k, used=v)
        if rnd.random() < RATES["vocab"] and "environment" in r["tags"]:
            r["tags"]["environment"] = TYPO[r["tags"]["environment"]]
            plant("vocab", r, key="environment")
        if r["provider"] == "GCP" and rnd.random() < RATES["case"] * 4:
            r["tags"]["Project"] = "x"
            plant("case", r, key="Project")
        if rnd.random() < RATES["long"] and PROVIDERS[r["provider"]][1]:
            mx = PROVIDERS[r["provider"]][1]
            r["tags"]["note-" + "x" * mx] = "y"
            plant("long", r, key="note-" + "x" * mx)
        if rnd.random() < RATES["foreign_prefix"] and r["provider"] != "AWS":
            r["tags"]["aws:migrated-from"] = "aws"
            plant("foreign_prefix", r, key="aws:migrated-from")
        if rnd.random() < RATES["conflict"] and r["tags"].get("environment") == "prod" and "data-classification" in r["tags"]:
            r["tags"]["data-classification"] = "public"
            plant("conflict", r)
        if rnd.random() < RATES["unmanaged"]:
            k = rnd.choice([u for u in UNMANAGED if r["provider"] != "GCP" or u.islower()])
            r["tags"][k] = "v"
            plant("unmanaged", r, key=k)
        if rnd.random() < RATES["typo_key"]:
            k = rnd.choice([k for k in TYPO_KEYS if k in r["tags"]] or [None])
            if k:
                r["tags"][TYPO_KEYS[k]] = r["tags"].pop(k)
                plant("typo_key", r, key=k, used=TYPO_KEYS[k])
    for r in res:
        if rnd.random() < RATES["no_owner"]:
            r["owners"] = []
            plant("no_owner", r)
        elif rnd.random() < RATES["two_owners"]:
            other = rnd.choice([t for t in teams if t["id"] != r["owners"][0]])
            r["owners"].append(other["id"])
            plant("two_owners", r)
        if rnd.random() < RATES["two_types"]:
            alt = next(t for t, p, *_ in TYPES if p == r["provider"] and t != r["type"])
            r["types"].append(alt)
            plant("two_types", r)
        r["provider_tags"] = dict(r["tags"])   # what the provider holds; the inventory may see less
        if rnd.random() < RATES["incomplete"]:
            r["complete"] = False
            if r["tags"]:   # the listing truncated the tag set
                drop = rnd.sample(sorted(r["tags"]), k=max(1, len(r["tags"]) // 2))
                for k in drop:
                    del r["tags"][k]
            plant("incomplete", r)
    m["resources"] = res
    m["planted"] = planted
    return m


ROLES_KEYS = {k for ks in ROLES.values() for k in ks} | {"backup-tier"}


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def to_ttl(m):
    L = [f"@prefix clo: <{CLO}> .", "@prefix owl: <http://www.w3.org/2002/07/owl#> .",
         "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .", "",
         f"<http://example.org/clo/data/synthetic-{m['seed']}> a owl:Ontology .", ""]
    keys, vals = {}, {}
    import hashlib
    safe = lambda x: hashlib.sha1(x.encode()).hexdigest()[:10]

    def key(name):
        if name not in keys:
            keys[name] = f"clo:k_{safe(name)}"
            L.append(f'{keys[name]} a clo:LabelKey , owl:NamedIndividual ; clo:keyName "{esc(name)}" .')
        return keys[name]

    def val(v):
        if v not in vals:
            vals[v] = f"clo:v_{safe(v)}"
            L.append(f'{vals[v]} a clo:LabelValue , owl:NamedIndividual ; clo:valueName "{esc(v)}" .')
        return vals[v]
    for role, ks in m["roles"].items():
        for k in ks:
            L.append(f"clo:{ROLE_IRI[role]} clo:needsLabel {key(k)} .")
    for k, srcs in m["value_source"].items():
        for s in srcs:
            L.append(f'{key(k)} clo:valueSource "{s}" .')
    for canon, syns in m["synonyms"].items():
        g = f"clo:syn_{canon.replace('-', '_')}"
        L.append(f'{g} a clo:SynonymGroup , owl:NamedIndividual ; clo:canonicalKey "{canon}" ; clo:hasMember '
                 + " , ".join(key(x) for x in [canon] + syns) + " .")
    for k, allowed in m["vocab"].items():
        v = f"clo:voc_{k.replace('-', '_')}"
        L.append(f"{v} a clo:LabelVocabulary , owl:NamedIndividual .")
        L.append(f"{key(k)} clo:hasVocabulary {v} .")
        for i, a in enumerate(allowed):
            av = f"clo:av_{k.replace('-', '_')}_{i}"
            L.append(f'{av} a clo:AllowedValue , owl:NamedIndividual ; clo:valueName "{a}" .')
            L.append(f"{v} clo:hasAllowedValue {av} .")
    for i, (ka, va, kb, vb) in enumerate(m["conflicts"]):
        L.append(f'clo:conflict{i} a clo:SemanticConflictRule , owl:NamedIndividual ; clo:conflictKeyA "{ka}" ; '
                 f'clo:conflictValueA "{va}" ; clo:conflictKeyB "{kb}" ; clo:conflictValueB "{vb}" .')
    for ou in m["ous"]:
        cls = "OrganizationalRoot" if ou["parent"] is None else "OrganizationalUnit"
        L.append(f"clo:{ou['id']} a clo:{cls} , owl:NamedIndividual"
                 + (f" ; clo:orgPartOf clo:{ou['parent']}" if ou["parent"] else "") + " .")
    for a in m["accounts"]:
        L.append(f"clo:{a['id']} a clo:Account , owl:NamedIndividual ; clo:orgPartOf clo:{a['ou']} .")
    for t in m["teams"]:
        L.append(f'clo:{t["id"]} a clo:Team , owl:NamedIndividual ; rdfs:label "{t["name"]}" ; clo:orgPartOf clo:{t["ou"]} .')
    for p in m["policies"]:
        L.append(f'clo:{p["id"]} a clo:LabelingPolicy , owl:NamedIndividual ; rdfs:label "{p["label"]}" .')
        for ro in p["serves"]:
            L.append(f"clo:{p['id']} clo:servesRole clo:{ROLE_IRI[ro]} .")
        for k in p["requires"]:
            L.append(f"clo:{p['id']} clo:requiresLabel {key(k)} .")
        kind, target = p["attach"]
        if kind in ("ou", "account", "team"):
            L.append(f"clo:{target} clo:governedBy clo:{p['id']} .")
        elif kind == "category":
            L.append(f"clo:{p['id']} clo:appliesToCategory clo:{target} .")
    for r in m["resources"]:
        parts = [f'clo:{r["id"]} a clo:CloudResource , owl:NamedIndividual ; clo:resourceId "{r["id"]}"',
                 "clo:hasResourceType " + " , ".join(f"clo:rt_{t}" for t in r["types"]),
                 f"clo:belongsToAccount clo:{r['account']}",
                 f"clo:recordComplete {'true' if r['complete'] else 'false'}"]
        if r["owners"]:
            parts.append("clo:ownedBy " + " , ".join(f"clo:{t}" for t in r["owners"]))
        if r["parent"]:
            parts.append(f"clo:partOf clo:{r['parent']}")
        ls = []
        for i, (k, v) in enumerate(sorted(r["tags"].items())):
            li = f"clo:{r['id']}_l{i}"
            ls.append(li)
            L.append(f"{li} a clo:Label , owl:NamedIndividual ; clo:hasLabelKey {key(k)} ; clo:hasLabelValue {val(v)} .")
        if ls:
            parts.append("clo:hasLabel " + " , ".join(ls))
        L.append(" ;\n    ".join(parts) + " .")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", required=True, help="output prefix")
    a = ap.parse_args()
    m = build(a.n, a.seed)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(m, open(a.out + ".json", "w"), indent=0)
    open(a.out + ".ttl", "w").write(to_ttl(m))
    labels = sum(len(r["tags"]) for r in m["resources"])
    print(f"{a.out}: {len(m['resources'])} resources, {labels} labels, {len(m['teams'])} teams, "
          f"{len(m['planted'])} planted defects")


if __name__ == "__main__":
    sys.exit(main())
