#!/usr/bin/env python3
"""
ingest_c7n.py -- build a CLO inventory from Cloud Custodian's recorded API responses.

Cloud Custodian (Apache-2.0) ships, as test fixtures, thousands of provider API
responses recorded against real AWS, Azure and GCP accounts:
  tests/data/placebo/<flight>/<service>.<Operation>_<n>.json          (AWS, boto3)
  tools/c7n_azure/tests_azure/cassettes/<test>.json                   (Azure, ARM)
  tools/c7n_gcp/tests/data/flights/<flight>/<request>_<n>.json        (GCP REST)
They were produced by an independent project for its own purposes, which makes
them a useful open corpus of real response shapes, real tag spellings and real
gaps in what a listing returns.

Monitor step of the cycle. For every record we derive, from the response itself:
  * the CLO resource type (catalogue kind) -- or count the record as unmapped;
  * the tag set;
  * recordComplete, by provider-specific rules (RULES below), never by default;
  * the account / subscription / project, used as the organisational anchor.
Resource identifiers, and tag values other than those of categorical keys
(environment, application, cost centre, classification, ...), are replaced by
stable pseudonyms; no other response field is kept. Key names are kept as
published upstream.

  python3 tools/ingest_c7n.py --c7n ../cloud-custodian --out data/open/c7n_inventory.ttl \
      --report data/open/c7n_ingest_report.json
"""
import argparse
import collections
import hashlib
import json
import os
import re
import sys

CLO = "http://example.org/clo/ontology/clo#"

# ── Record-completeness rules (documented in the paper, Table "completeness") ──
RULES = {
    "A1": "AWS: the record carries a Tags/TagList/TagSet field (possibly empty)",
    "A2": "AWS: EC2/AutoScaling/RDS Describe* response shape embeds tags; an absent field means no tag",
    "A3": "AWS: Resource Groups Tagging API record (all tags of a tagged resource)",
    "Z1": "Azure: the ARM record carries a tags field (possibly empty)",
    "G1": "GCP: the record carries labels or labelFingerprint (empty maps are omitted)",
    "N":  "listing that never returns tags (e.g. s3 ListBuckets, iam ListRoles, lambda ListFunctions): no verdict",
}
TAG_EMBEDDING_OPS = re.compile(r"^(ec2\.Describe(Instances|Volumes|Snapshots|Vpcs|Subnets|SecurityGroups|"
                               r"NetworkInterfaces|RouteTables|InternetGateways|NatGateways|Addresses|"
                               r"VpcEndpoints|NetworkAcls|KeyPairs|VpcPeeringConnections)|"
                               r"autoscaling\.DescribeAutoScalingGroups|rds\.DescribeDB(Instances|Clusters))$")

# ── AWS: primary records of Describe* operations, by (operation, id field, witness field) ──
AWS_PRIMARY = [
    (r"ec2\.DescribeInstances", "InstanceId", "InstanceType", "aws_ec2_instance"),
    (r"ec2\.DescribeVolumes", "VolumeId", "Size", "aws_ec2_volume"),
    (r"ec2\.DescribeSnapshots", "SnapshotId", "VolumeSize", "aws_ec2_snapshot"),
    (r"ec2\.DescribeVpcs", "VpcId", "CidrBlock", "aws_vpc"),
    (r"ec2\.DescribeSubnets", "SubnetId", "CidrBlock", "aws_ec2_subnet"),
    (r"ec2\.DescribeSecurityGroups", "GroupId", "IpPermissions", "aws_ec2_security_group"),
    (r"ec2\.DescribeNetworkInterfaces", "NetworkInterfaceId", "InterfaceType", "aws_ec2_network_interface"),
    (r"ec2\.DescribeRouteTables", "RouteTableId", "Routes", "aws_ec2_route_table"),
    (r"ec2\.DescribeInternetGateways", "InternetGatewayId", "Attachments", "aws_ec2_internet_gateway"),
    (r"ec2\.DescribeNatGateways", "NatGatewayId", "NatGatewayAddresses", "aws_ec2_nat_gateway"),
    (r"ec2\.DescribeAddresses", "AllocationId", "PublicIp", "aws_ec2_elastic_ip"),
    (r"ec2\.DescribeVpcEndpoints", "VpcEndpointId", "ServiceName", "aws_vpc_endpoint"),
    (r"ec2\.DescribeNetworkAcls", "NetworkAclId", "Entries", "aws_ec2_network_acl"),
    (r"ec2\.DescribeKeyPairs", "KeyPairId", "KeyName", "aws_ec2_keypair"),
    (r"ec2\.DescribeVpcPeeringConnections", "VpcPeeringConnectionId", "RequesterVpcInfo", "aws_vpc_peering_connection"),
    (r"autoscaling\.DescribeAutoScalingGroups", "AutoScalingGroupName", "MinSize", "aws_autoscaling_group"),
    (r"rds\.DescribeDBInstances", "DBInstanceIdentifier", "DBInstanceClass", "aws_rds_instance"),
    (r"rds\.DescribeDBClusters", "DBClusterIdentifier", "DBClusterMembers", "aws_rds_cluster"),
    (r"rds\.DescribeDBSnapshots", "DBSnapshotIdentifier", "SnapshotCreateTime", "aws_rds_snapshot"),
    (r"s3\.ListBuckets", "Name", "CreationDate", "aws_s3_bucket"),
    (r"iam\.(GetRole|ListRoles)", "RoleName", "AssumeRolePolicyDocument", "aws_iam_role"),
    (r"iam\.(GetUser|ListUsers)", "UserName", "UserId", "aws_iam_user"),
    (r"iam\.ListGroups", "GroupName", "GroupId", "aws_iam_group"),
    (r"lambda\.(ListFunctions|GetFunction)", "FunctionName", "Runtime", "aws_lambda_function"),
    (r"dynamodb\.DescribeTable", "TableName", "KeySchema", "aws_dynamodb_table"),
    (r"elasticfilesystem\.DescribeFileSystems", "FileSystemId", "LifeCycleState", "aws_efs_file_system"),
    (r"cloudformation\.DescribeStacks", "StackName", "StackStatus", "aws_cloudformation_stack"),
    (r"eks\.DescribeCluster", "name", "roleArn", "aws_eks_cluster"),
]
# ── AWS ARNs (tagging API and records carrying an ARN) ──
ARN_MAP = [
    ("ec2", "instance", "aws_ec2_instance"), ("ec2", "volume", "aws_ec2_volume"),
    ("ec2", "snapshot", "aws_ec2_snapshot"), ("ec2", "vpc", "aws_vpc"),
    ("ec2", "subnet", "aws_ec2_subnet"), ("ec2", "security-group", "aws_ec2_security_group"),
    ("ec2", "network-interface", "aws_ec2_network_interface"), ("ec2", "route-table", "aws_ec2_route_table"),
    ("ec2", "internet-gateway", "aws_ec2_internet_gateway"), ("ec2", "natgateway", "aws_ec2_nat_gateway"),
    ("ec2", "elastic-ip", "aws_ec2_elastic_ip"), ("ec2", "vpc-endpoint", "aws_vpc_endpoint"),
    ("ec2", "network-acl", "aws_ec2_network_acl"), ("ec2", "key-pair", "aws_ec2_keypair"),
    ("ec2", "vpc-peering-connection", "aws_vpc_peering_connection"),
    ("rds", "db", "aws_rds_instance"), ("rds", "cluster", "aws_rds_cluster"),
    ("rds", "snapshot", "aws_rds_snapshot"), ("lambda", "function", "aws_lambda_function"),
    ("dynamodb", "table", "aws_dynamodb_table"), ("iam", "role", "aws_iam_role"),
    ("iam", "user", "aws_iam_user"), ("iam", "policy", "aws_iam_policy"), ("iam", "group", "aws_iam_group"),
    ("kms", "key", "aws_kms_key"), ("elasticloadbalancing", "loadbalancer/app", "aws_alb"),
    ("elasticloadbalancing", "loadbalancer/net", "aws_alb"), ("elasticloadbalancing", "loadbalancer", "aws_elb"),
    ("autoscaling", "autoScalingGroup", "aws_autoscaling_group"), ("cloudformation", "stack", "aws_cloudformation_stack"),
    ("eks", "cluster", "aws_eks_cluster"), ("elasticfilesystem", "file-system", "aws_efs_file_system"),
    ("route53", "hostedzone", "aws_route53_zone"), ("acm", "certificate", "aws_acm_certificate"),
    ("bedrock", "evaluation-job", "aws_bedrock_evaluation_job"), ("bedrock", "custom-model", "aws_bedrock_custom_model"),
    ("bedrock", "model-customization-job", "aws_bedrock_model_customization_job"),
    ("wafv2", "regional/webacl", "aws_waf_web_acl"), ("wafv2", "global/webacl", "aws_waf_web_acl"),
]
AZURE_MAP = {
    "microsoft.compute/virtualmachines": "azure_compute_virtual_machine",
    "microsoft.compute/disks": "azure_compute_disk",
    "microsoft.compute/snapshots": "azure_compute_virtual_machine_snapshot",
    "microsoft.compute/virtualmachinescalesets": "azure_compute_virtual_machine_scale_set",
    "microsoft.compute/sshpublickeys": "azure_compute_ssh_public_key",
    "microsoft.network/networksecuritygroups": "azure_network_security_group",
    "microsoft.network/networkinterfaces": "azure_network_interface",
    "microsoft.network/loadbalancers": "azure_network_load_balancer",
    "microsoft.network/publicipaddresses": "azure_network_public_ip_address",
    "microsoft.network/virtualnetworks": "azure_network_virtual_network",
    "microsoft.network/virtualnetworks/subnets": "azure_network_subnet",
    "microsoft.network/routetables": "azure_network_route_table",
    "microsoft.network/applicationgateways": "azure_network_application_gateway",
    "microsoft.network/azurefirewalls": "azure_network_firewall",
    "microsoft.network/firewallpolicies": "azure_network_firewall_policy",
    "microsoft.network/dnszones": "azure_network_dns_zone",
    "microsoft.network/virtualnetworkgateways": "azure_network_virtual_network_gateway",
    "microsoft.resources/resourcegroups": "azure_resource_group",
    "microsoft.sql/servers/databases": "azure_sql_server_database",
    "microsoft.documentdb/databaseaccounts": "azure_cosmos_db_account",
    "microsoft.dbformysql/servers": "azure_mysql_server",
    "microsoft.dbforpostgresql/servers": "azure_postgresql_server",
    "microsoft.containerservice/managedclusters": "azure_container_service_managed_cluster",
    "microsoft.web/sites": "azure_web_app",
}
GCP_MAP = {
    "compute#instance": "gcp_instance", "compute#disk": "gcp_disk", "compute#snapshot": "gcp_snapshot",
    "compute#address": "gcp_address", "compute#forwardingRule": "gcp_forwarding_rule",
    "compute#subnetwork": "gcp_subnetwork", "compute#firewall": "gcp_firewall", "compute#network": "gcp_network",
    "compute#autoscaler": "gcp_autoscaler", "compute#instanceGroup": "gcp_instance_group",
    "compute#sslCertificate": "gcp_ssl_certificate", "compute#vpnGateway": "gcp_vpn_gateway",
    "compute#backendBucket": "gcp_backend_bucket", "storage#bucket": "gcp_bucket",
    "sql#instance": "gcp_sql_database_instance", "container#cluster": "gcp_container_cluster",
}
# ── Catalogue extension (UC4): hand-mapped types observed in the open corpus, each with
#    positive evidence of tag support in the recorded responses (see extend_catalogue.py) ──
ARN_EXT = [("elasticache", "cluster", "aws_elasticache_cluster"), ("elasticache", "snapshot", "aws_elasticache_snapshot"),
           ("fsx", "file-system", "aws_fsx_file_system"), ("fsx", "backup", "aws_fsx_backup"),
           ("dsql", "cluster", "aws_dsql_cluster"), ("bedrock", "model-invocation-job", "aws_bedrock_model_invocation_job"),
           ("comprehend", "entity-recognizer", "aws_comprehend_entity_recognizer")]
AZURE_EXT = {"microsoft.storage/storageaccounts": "azure_storage_account", "microsoft.sql/servers": "azure_sql_server"}
GCP_EXT = {"dns#managedZone": "gcp_dns_managed_zone"}
PERSON_KEY = re.compile(r"(owner|creator|created.?by|contact|e-?mail|user)", re.I)


# Values are kept verbatim only for keys whose values are categorical and non-personal
# (environment-, application-, cost- and classification-like keys); every other value is
# replaced by a stable pseudonym, so equality between values is preserved but no name is.
KEEP_VALUE = re.compile(r"^(env|environment|stage|tier|app|application|service|costcent(er|re)|"
                        r"datacla(ss|ssification)|managedby|backuptier|workloadtype|platform|type|role)$")


def pseudo(key, value):
    if KEEP_VALUE.match(re.sub(r"[-_ .:/]", "", key.lower())) and not PERSON_KEY.search(key) and "@" not in value:
        return value
    return "p-" + hashlib.sha256(value.encode()).hexdigest()[:8]


def tags_of(rec):
    """(tags dict, field present?) from a provider record."""
    for f in ("Tags", "TagList", "TagSet", "tags"):
        if f in rec:
            v = rec[f]
            if isinstance(v, list):
                return {t.get("Key", t.get("key")): str(t.get("Value", t.get("value", ""))) for t in v
                        if isinstance(t, dict) and ("Key" in t or "key" in t)}, True
            if isinstance(v, dict):
                return {str(k): str(x) for k, x in v.items()}, True
    return {}, False


class Inv:
    def __init__(self):
        self.obs = collections.defaultdict(list)   # (provider, kind, id) -> [observation]
        self.unmapped = collections.Counter()
        self.unmapped_ids = collections.defaultdict(set)
        self.mapped_records = 0

    def add(self, provider, kind, rid, account, tags, complete, rule, src):
        self.mapped_records += 1
        self.obs[(provider, kind, rid)].append(
            {"account": account, "tags": tags, "complete": complete, "rule": rule, "src": src})


def unmapped(inv, t, rid):
    inv.unmapped[t] += 1
    inv.unmapped_ids[t].add(rid)


def arn_kind(arn):
    p = arn.split(":", 5)
    if len(p) < 6:
        return None, None, None
    svc, acct, res = p[2], p[4], p[5]
    if svc == "s3":
        return "aws_s3_bucket", res.split("/")[0], acct or None
    if svc == "sqs":
        return "aws_sqs_queue", res, acct
    best = None
    for s, prefix, kind in ARN_MAP:
        if s == svc and (res.startswith(prefix + "/") or res.startswith(prefix + ":")):
            if best is None or len(prefix) > len(best[0]):
                best = (prefix, kind)
    if not best:
        return None, svc + ":" + re.split(r"[/:]", res)[0], acct
    rid = res[len(best[0]) + 1:]
    if svc == "ec2":
        rid = rid.split("/")[-1]
    return best[1], rid, acct


def walk(x, fn):
    if isinstance(x, dict):
        fn(x)
        for v in x.values():
            walk(v, fn)
    elif isinstance(x, list):
        for v in x:
            walk(v, fn)


def ingest_aws(root, inv):
    for flight in sorted(os.listdir(root)):
        fd = os.path.join(root, flight)
        if not os.path.isdir(fd):
            continue
        files = sorted(f for f in os.listdir(fd) if f.endswith(".json"))
        datas = []
        for f in files:
            try:
                datas.append((f, json.load(open(os.path.join(fd, f))).get("data", {})))
            except Exception:
                continue
        # flight account: most common account id in ARNs of the flight
        accts = collections.Counter()
        for _, d in datas:
            for m in re.finditer(r"arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):", json.dumps(d)):
                accts[m.group(1)] += 1
        facct = accts.most_common(1)[0][0] if accts else "unknown"
        for f, d in datas:
            op = f.rsplit("_", 1)[0]
            src = f"{flight}/{f}"
            if op == "tagging.GetResources":
                for m in d.get("ResourceTagMappingList", []):
                    kind, rid, acct = arn_kind(m.get("ResourceARN", ""))
                    if not kind:
                        unmapped(inv, "aws " + (rid or "?"), m.get("ResourceARN"))
                        continue
                    t, _ = tags_of(m)
                    inv.add("AWS", kind, rid, acct or facct, t, True, "A3", src)
                continue
            for pat, idf, wit, kind in AWS_PRIMARY:
                if re.fullmatch(pat, op):
                    def fn(rec, idf=idf, wit=wit, kind=kind):
                        if idf in rec and wit in rec and isinstance(rec[idf], str):
                            t, present = tags_of(rec)
                            if present:
                                c, rule = True, "A1"
                            elif TAG_EMBEDDING_OPS.match(op):
                                c, rule = True, "A2"
                            else:
                                c, rule = False, "N"
                            acct = rec.get("OwnerId") if re.fullmatch(r"\d{12}", str(rec.get("OwnerId", ""))) else facct
                            inv.add("AWS", kind, rec[idf], acct, t, c, rule, src)
                    walk(d, fn)
                    break
            else:
                # any other record carrying both an ARN and a tag field
                def fn(rec):
                    arn = next((rec[k] for k in ("ResourceARN", "Arn", "ARN", "arn", "ResourceArn")
                                if isinstance(rec.get(k), str) and rec[k].startswith("arn:")), None)
                    if not arn:
                        return
                    t, present = tags_of(rec)
                    if not present:
                        return
                    kind, rid, acct = arn_kind(arn)
                    if not kind:
                        unmapped(inv, "aws " + (rid or "?"), arn)
                        return
                    inv.add("AWS", kind, rid, acct or facct, t, True, "A1", src)
                walk(d, fn)


def ingest_azure(root, inv):
    for f in sorted(os.listdir(root)):
        try:
            d = json.load(open(os.path.join(root, f)))
        except Exception:
            continue
        for i, it in enumerate(d.get("interactions", [])):
            body = it.get("response", {}).get("body", {})
            data = body.get("data") if isinstance(body.get("data"), (dict, list)) else None
            if data is None and isinstance(body.get("string"), str):
                try:
                    data = json.loads(body["string"])
                except Exception:
                    continue
            if data is None:
                continue

            def fn(rec):
                rid, typ = rec.get("id"), rec.get("type")
                if not (isinstance(rid, str) and isinstance(typ, str) and rid.lower().startswith("/subscriptions/")):
                    return
                typ = typ.lower()
                kind = AZURE_MAP.get(typ)
                if not kind:
                    unmapped(inv, "azure " + typ, rid.lower())
                    return
                sub = rid.split("/")[2].lower()
                t, present = tags_of(rec)
                inv.add("Azure", kind, rid.lower(), sub, t, present, "Z1" if present else "N", f"{f}#{i}")
            walk(data, fn)


def ingest_gcp(root, inv):
    for flight in sorted(os.listdir(root)):
        fd = os.path.join(root, flight)
        if not os.path.isdir(fd):
            continue
        for f in sorted(os.listdir(fd)):
            try:
                body = json.load(open(os.path.join(fd, f))).get("body")
            except Exception:
                continue

            def fn(rec):
                k = rec.get("kind")
                if not (isinstance(k, str) and "#" in k):
                    return
                if k.endswith("List") or "aggregated" in k.lower() or k.endswith("Operation") or "operation" in k.lower():
                    return
                ident = rec.get("selfLink") or rec.get("id") or rec.get("name")
                if not isinstance(ident, str):
                    return
                kind = GCP_MAP.get(k)
                if not kind:
                    if "labels" in rec or "labelFingerprint" in rec:
                        unmapped(inv, "gcp " + k, ident)
                    return
                m = re.search(r"projects/([^/]+)/", ident) or re.search(r"projects/([^/]+)/", json.dumps(rec))
                proj = m.group(1) if m else rec.get("projectNumber", rec.get("project", "unknown"))
                labels = rec.get("labels") if isinstance(rec.get("labels"), dict) else {}
                present = "labels" in rec or "labelFingerprint" in rec
                rid = re.sub(r"^https://[^/]+/", "", ident)
                inv.add("GCP", kind, rid, str(proj), {str(a): str(b) for a, b in labels.items()},
                        present, "G1" if present else "N", f"{flight}/{f}")
            walk(body, fn)


def choose(obs):
    """One record per resource: prefer complete observations, then the last in source order."""
    comp = [o for o in obs if o["complete"]]
    pick = (comp or obs)[-1]
    distinct = {json.dumps(o["tags"], sort_keys=True) for o in comp}
    return pick, len(distinct) > 1


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--c7n", required=True, help="Cloud Custodian checkout")
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--json", help="also write the inventory as JSON (for the baselines)")
    ap.add_argument("--no-ext", action="store_true", help="catalogue as released, without the extension")
    a = ap.parse_args()
    if not a.no_ext:
        ARN_MAP.extend(ARN_EXT); AZURE_MAP.update(AZURE_EXT); GCP_MAP.update(GCP_EXT)
    inv = Inv()
    ingest_aws(os.path.join(a.c7n, "tests/data/placebo"), inv)
    ingest_azure(os.path.join(a.c7n, "tools/c7n_azure/tests_azure/cassettes"), inv)
    ingest_gcp(os.path.join(a.c7n, "tools/c7n_gcp/tests/data/flights"), inv)

    H = lambda s: hashlib.sha256(s.encode()).hexdigest()[:12]
    keys, vals, accts, teams = {}, {}, set(), {}
    lines = [f"@prefix clo: <{CLO}> .", "@prefix owl: <http://www.w3.org/2002/07/owl#> .",
             "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .", "",
             "<http://example.org/clo/data/c7n-inventory> a owl:Ontology ;",
             '    rdfs:comment "CLO inventory derived from Cloud Custodian recorded API responses (Apache-2.0)." .', ""]
    rows, conflicts, by_rule = [], 0, collections.Counter()
    for (prov, kind, rid), obs in sorted(inv.obs.items()):
        pick, conflict = choose(obs)
        conflicts += conflict
        by_rule[pick["rule"]] += 1
        r = "clo:r_" + H(prov + kind + rid)
        acct = f"clo:acct_{prov.lower()}_{H(pick['account'])}"
        accts.add(acct)
        labels = []
        tags = {k: pseudo(k, v) for k, v in pick["tags"].items() if k is not None}
        for k, v in sorted(tags.items()):
            ki = "clo:k_" + H(k)
            vi = "clo:v_" + H(v)
            keys[ki] = k
            vals[vi] = v
            li = "clo:l_" + H(r + k)
            labels.append(li)
            lines.append(f"{li} a clo:Label , owl:NamedIndividual ; clo:hasLabelKey {ki} ; clo:hasLabelValue {vi} .")
        pid = f"{kind}-{H(prov + kind + rid)}"     # resource ids are pseudonymised too
        body = (f'{r} a clo:CloudResource , owl:NamedIndividual ; clo:resourceId "{pid}" ;'
                f" clo:hasResourceType clo:rt_{kind} ; clo:belongsToAccount {acct} ;"
                f" clo:recordComplete {'true' if pick['complete'] else 'false'}")
        if labels:
            body += " ; clo:hasLabel " + " , ".join(labels)
        lines.append(body + " .")
        rows.append({"iri": r[4:], "provider": prov, "kind": kind, "id": pid, "account": acct[4:],
                     "complete": pick["complete"], "rule": pick["rule"], "tags": tags,
                     "observations": len(obs), "src": pick["src"]})
    for ki, k in sorted(keys.items()):
        lines.append(f'{ki} a clo:LabelKey , owl:NamedIndividual ; clo:keyName "{esc(k)}" .')
    for vi, v in sorted(vals.items()):
        lines.append(f'{vi} a clo:LabelValue , owl:NamedIndividual ; clo:valueName "{esc(v)}" .')
    for ac in sorted(accts):
        lines.append(f"{ac} a clo:Account , owl:NamedIndividual .")
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    open(a.out, "w").write("\n".join(lines) + "\n")
    if a.json:
        json.dump(rows, open(a.json, "w"), indent=0)
    prov_count = collections.Counter(r["provider"] for r in rows)
    kind_count = collections.Counter(r["kind"] for r in rows)
    rep = {"resources": len(rows), "by_provider": prov_count, "kinds": len(kind_count),
           "by_kind": dict(kind_count.most_common()), "mapped_records": inv.mapped_records,
           "unmapped_records": sum(inv.unmapped.values()), "unmapped_types": len(inv.unmapped),
           "unmapped_resources": sum(len(v) for v in inv.unmapped_ids.values()),
           "unmapped_resources_by_type": {k: len(v) for k, v in sorted(inv.unmapped_ids.items(), key=lambda x: -len(x[1]))},
           "unmapped_top": inv.unmapped.most_common(40), "completeness_rule": by_rule,
           "complete": sum(r["complete"] for r in rows), "tagged": sum(bool(r["tags"]) for r in rows),
           "labels": sum(len(r["tags"]) for r in rows), "distinct_keys": len(keys),
           "conflicting_observations": conflicts, "accounts": len(accts), "rules": RULES}
    json.dump(rep, open(a.report, "w"), indent=1)
    print(json.dumps({k: rep[k] for k in ("resources", "by_provider", "kinds", "mapped_records", "unmapped_records", "unmapped_resources",
                                          "unmapped_types", "completeness_rule", "complete", "tagged", "labels",
                                          "distinct_keys", "conflicting_observations", "accounts")}))


if __name__ == "__main__":
    sys.exit(main())
