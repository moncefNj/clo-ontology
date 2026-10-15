#!/usr/bin/env python3
"""
clo_compile.py -- the Execute step: compile CLO's derived standard and its repair
plan into provider-native artefacts. CLO decides what the shared standard is;
the provider tools enforce the part of it they can express.

From the materialised graph (tools/clo_audit.py --out-dir D writes D/inferred.nt):
  aws_config.json     CloudFormation resources for AWS Config REQUIRED_TAGS (<= 6 keys per
                      rule): an OrganizationConfigRule organisation-wide, ConfigRules for
                      OUs and accounts (StackSet targets in Metadata); category policies
                      are scoped to the category's AWS resource types (clo/native.py)
  azure_policy.json   assignments of the built-in "Require a tag on resources" (one per key
                      and management group or subscription); category policies become a
                      custom audit definition on the category's resource types
  custodian.yml       Cloud Custodian policies for GCP and Kubernetes resource types
  repairs.sh          the plan's value-carrying repairs as dry-run CLI commands
  coverage.json       which (policy, key, scope) requirements were compiled, and which
                      stay in CLO only (team scope, composition inheritance, roles)

  python3 tools/clo_compile.py --in-dir out --out-dir out/enforce
"""
import argparse
import collections
import json
import os
import shlex
import sys

import pyoxigraph as ox
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from clo import native as NV  # noqa: E402
from clo.audit import _q, loc  # noqa: E402

# Catalogue kinds among the 30 resource types AWS Config's REQUIRED_TAGS rule evaluates
CFN = {"aws_ec2_instance": "AWS::EC2::Instance", "aws_ec2_volume": "AWS::EC2::Volume", "aws_s3_bucket": "AWS::S3::Bucket",
       "aws_rds_instance": "AWS::RDS::DBInstance", "aws_rds_snapshot": "AWS::RDS::DBSnapshot", "aws_vpc": "AWS::EC2::VPC",
       "aws_ec2_subnet": "AWS::EC2::Subnet", "aws_autoscaling_group": "AWS::AutoScaling::AutoScalingGroup",
       "aws_dynamodb_table": "AWS::DynamoDB::Table", "aws_ec2_security_group": "AWS::EC2::SecurityGroup",
       "aws_ec2_internet_gateway": "AWS::EC2::InternetGateway", "aws_ec2_network_acl": "AWS::EC2::NetworkAcl",
       "aws_ec2_network_interface": "AWS::EC2::NetworkInterface", "aws_ec2_route_table": "AWS::EC2::RouteTable",
       "aws_cloudformation_stack": "AWS::CloudFormation::Stack", "aws_acm_certificate": "AWS::ACM::Certificate",
       "aws_elb": "AWS::ElasticLoadBalancing::LoadBalancer", "aws_alb": "AWS::ElasticLoadBalancingV2::LoadBalancer"}
ARM = {"azure_compute_virtual_machine": "Microsoft.Compute/virtualMachines", "azure_compute_disk": "Microsoft.Compute/disks",
       "azure_sql_server_database": "Microsoft.Sql/servers/databases", "azure_sql_server": "Microsoft.Sql/servers",
       "azure_network_virtual_network": "Microsoft.Network/virtualNetworks",
       "azure_cosmos_db_account": "Microsoft.DocumentDB/databaseAccounts",
       "azure_mysql_server": "Microsoft.DBforMySQL/servers", "azure_postgresql_server": "Microsoft.DBforPostgreSQL/servers"}
C7N = {"gcp_instance": "gcp.instance", "gcp_disk": "gcp.disk", "gcp_bucket": "gcp.bucket",
       "gcp_sql_database_instance": "gcp.sql-instance", "gcp_snapshot": "gcp.snapshot",
       "kubernetes_node": "k8s.node", "kubernetes_service": "k8s.service", "kubernetes_persistent_volume": "k8s.volume"}


def compile_graph(st):
    req = collections.defaultdict(set)
    for r in _q(st, "SELECT ?p ?n WHERE { ?p clo:requiresLabel/clo:keyName ?n }"):
        req[r["p"]].add(r["n"])
    attach = []
    for r in _q(st, """SELECT ?p ?s ?kind WHERE { ?s clo:governedBy ?p . ?p a clo:LabelingPolicy .
            { ?s a clo:OrganizationalRoot . BIND("root" AS ?kind) } UNION { ?s a clo:OrganizationalUnit . BIND("ou" AS ?kind) }
            UNION { ?s a clo:Account . BIND("account" AS ?kind) } UNION { ?s a clo:Team . BIND("team" AS ?kind) } }"""):
        attach.append((r["p"], r["kind"], loc(r["s"])))
    for r in _q(st, "SELECT ?p ?c WHERE { ?p clo:appliesToCategory ?c }"):
        attach.append((r["p"], "category", loc(r["c"])))
    types_of = collections.defaultdict(list)
    for r in _q(st, """SELECT ?c ?n WHERE { ?t a clo:ResourceType ; clo:resourceTypeName ?n ; clo:implementsBaseKind/clo:categoryOf ?c .
                       { ?t a clo:FullyTaggableType } UNION { ?t a clo:PartiallyTaggableType } }"""):
        types_of[loc(r["c"])].append(r["n"])
    aws, az, c7n, cov = [], [], [], []
    for p, kind, tgt in sorted(attach):
        keys = sorted(req.get(p, ()))
        if not keys:
            continue
        if kind == "team":
            cov.append({"policy": loc(p), "scope": f"team:{tgt}", "keys": keys, "compiled": False,
                        "why": "no team scope in AWS Config, Azure Policy or Custodian; enforced by CLO's audit only"})
            continue
        scope = {"root": "organization", "ou": f"ou:{tgt}", "account": f"account:{tgt}", "category": "organization"}[kind]
        aws_types = [CFN[t] for t in sorted(types_of[tgt]) if t in CFN] if kind == "category" else None
        az_types = [ARM[t] for t in sorted(types_of[tgt]) if t in ARM] if kind == "category" else None
        c7n_types = sorted({C7N[t] for t in (types_of[tgt] if kind == "category" else C7N) if t in C7N})
        akind = {"root": "organization", "category": "organization", "ou": "ou", "account": "account"}[kind]
        sid = "root" if kind in ("root", "category") else tgt
        name = f"clo-{loc(p)}".replace("_", "-")
        if aws_types is None or aws_types:
            aws += NV.aws_rules(name, akind, sid, keys, aws_types)
        if az_types is None or az_types:
            az += NV.azure_items(name, "account" if kind == "account" else "mg", sid, keys, az_types)
        for res in c7n_types:
            tk = (lambda k: f'labels."{k}"') if res.startswith("gcp.") else (lambda k: f'metadata.labels."{k}"')
            act = ({"type": "notify", "to": ["resource-owner"], "template": "default",
                    "transport": {"type": "pubsub", "topic": "projects/example/topics/clo"}} if res.startswith("gcp.")
                   else {"type": "label", "labels": {"clo-missing-labels": "true"}})
            c7n.append({"name": f"clo-{loc(p)}-{res}".replace("_", "-").replace(".", "-"), "resource": res,
                        "comment": f"CLO policy {loc(p)}, scope {scope}",
                        "filters": [{"or": [{tk(k): "absent"} for k in keys]}], "actions": [act]})
        cov.append({"policy": loc(p), "scope": scope, "keys": keys, "compiled": True})
    cov.append({"policy": "*", "scope": "partOf", "compiled": False,
                "why": "composition inheritance (C-3) has no provider-native equivalent; CLO's audit only"})
    return aws, az, c7n, cov


def repairs(findings):
    L = ["#!/bin/sh", "# Dry run: review, then remove 'echo'. Generated by tools/clo_compile.py from findings.json.", "set -eu"]
    for f in findings["findings"]:
        if f["rule"] not in ("I-07", "I-22") or not f.get("repair"):
            continue
        rid = f["resource"]
        r = findings["resources"].get(f["iri"].split("#")[-1], {}) if f.get("iri") else {}
        prov = (r.get("provider") or "").lower()
        if f["rule"] == "I-22":
            k_new, k_old = f["key"], f.get("used")
            L.append(f"# {rid}: rename {k_old} -> {k_new} ({', '.join(f.get('roles') or [])})")
            if prov == "aws":
                L.append(f"echo aws resourcegroupstaggingapi tag-resources --resource-arn-list {shlex.quote(rid)} "
                         f"--tags {shlex.quote(k_new)}=<value-of-{k_old}> && echo aws resourcegroupstaggingapi "
                         f"untag-resources --resource-arn-list {shlex.quote(rid)} --tag-keys {shlex.quote(k_old)}")
            elif prov == "azure":
                L.append(f"echo az tag update --resource-id {shlex.quote(rid)} --operation merge --tags "
                         f"{shlex.quote(k_new)}=<value-of-{k_old}>")
            else:
                L.append(f"echo '# relabel {rid}: {k_old} -> {k_new}'")
            continue
        v = f.get("repair_value")
        if v is None:
            continue
        kv = shlex.quote(f"{f['key']}={v}")
        L.append(f"# {rid}: {f['repair']}")
        if prov == "aws":
            L.append(f"echo aws resourcegroupstaggingapi tag-resources --resource-arn-list {shlex.quote(rid)} --tags {kv}")
        elif prov == "azure":
            L.append(f"echo az tag update --resource-id {shlex.quote(rid)} --operation merge --tags {kv}")
        elif prov == "gcp":
            cmd = {"gcp_bucket": f"gcloud storage buckets update gs://{rid} --update-labels={kv}",
                   "gcp_instance": f"gcloud compute instances add-labels {rid} --labels={kv}",
                   "gcp_disk": f"gcloud compute disks add-labels {rid} --labels={kv}",
                   "gcp_sql_database_instance": f"gcloud sql instances patch {rid} --update-labels={kv}"}.get(r.get("type"))
            L.append(f"echo {cmd}" if cmd else f"echo '# set {kv} on {rid} ({r.get('type')})'")
        else:
            L.append(f"echo '# set {kv} on {rid} ({prov})'")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args()
    st = ox.Store()
    st.bulk_load(path=os.path.join(a.in_dir, "inferred.nt"), format=ox.RdfFormat.N_TRIPLES)
    aws, az, c7n, cov = compile_graph(st)
    os.makedirs(a.out_dir, exist_ok=True)
    json.dump(aws, open(os.path.join(a.out_dir, "aws_config.json"), "w"), indent=1)
    json.dump(az, open(os.path.join(a.out_dir, "azure_policy.json"), "w"), indent=1)
    yaml.safe_dump({"policies": c7n}, open(os.path.join(a.out_dir, "custodian.yml"), "w"), sort_keys=False)
    json.dump(cov, open(os.path.join(a.out_dir, "coverage.json"), "w"), indent=1)
    findings = json.load(open(os.path.join(a.in_dir, "findings.json")))
    open(os.path.join(a.out_dir, "repairs.sh"), "w").write(repairs(findings))
    print(f"{len(aws)} AWS Config rules, {len(az)} Azure Policy assignments, {len(c7n)} Custodian policies; "
          f"{sum(not c['compiled'] for c in cov)} requirement group(s) kept in CLO only")


if __name__ == "__main__":
    main()
