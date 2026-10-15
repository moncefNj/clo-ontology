#!/usr/bin/env python3
"""
extend_catalogue.py -- UC4 on real data: add resource types observed in the open
corpus that the Fix-Inventory-derived catalogue does not cover.

Each added type needs a BaseKind chosen by hand (EXT below). Its labelling
support is set by an evidence rule that respects the open-world reading:

  E+  at least one recorded response carries a non-empty tag set for the type
      -> labelingSupport "full" (positive evidence is conclusive);
  E?  no such response -> no labelingSupport assertion (unknown, out of scope
      until curated); absence of tags in responses proves nothing.

  python3 tools/extend_catalogue.py --inventory data/open/c7n_inventory.json \
      --out ontology/clo_types_ext.ttl
"""
import argparse
import collections
import json

CLO = "http://example.org/clo/ontology/clo#"
# kind -> (provider individual, BaseKind, provider type, approximation note)
EXT = {
    "aws_elasticache_cluster": ("AWS", "DatabaseKind", "elasticache:cluster", ""),
    "aws_elasticache_snapshot": ("AWS", "SnapshotKind", "elasticache:snapshot", ""),
    "aws_fsx_file_system": ("AWS", "NetworkShareKind", "fsx:file-system", ""),
    "aws_fsx_backup": ("AWS", "SnapshotKind", "fsx:backup", ""),
    "aws_dsql_cluster": ("AWS", "DatabaseKind", "dsql:cluster", ""),
    "aws_bedrock_model_invocation_job": ("AWS", "AIJobKind", "bedrock:model-invocation-job", ""),
    "aws_comprehend_entity_recognizer": ("AWS", "AIModelKind", "comprehend:entity-recognizer", ""),
    "azure_storage_account": ("Azure", "BucketKind", "Microsoft.Storage/storageAccounts",
                              "approximation: an account contains containers"),
    "azure_sql_server": ("Azure", "DatabaseKind", "Microsoft.Sql/servers", ""),
    "gcp_dns_managed_zone": ("GCP", "DNSZoneKind", "dns#managedZone", ""),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rows = json.load(open(a.inventory))
    seen, tagged = collections.Counter(), collections.Counter()
    for r in rows:
        seen[r["kind"]] += 1
        tagged[r["kind"]] += bool(r["tags"])
    out = [f"@prefix clo: <{CLO}> .", "@prefix owl: <http://www.w3.org/2002/07/owl#> .",
           "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .", "",
           "<http://example.org/clo/ontology/clo-types-ext> a owl:Ontology ;",
           '    rdfs:comment "Catalogue extension from the open Cloud Custodian corpus (tools/extend_catalogue.py)." .', ""]
    for kind, (prov, bk, src, note) in sorted(EXT.items()):
        ev = tagged[kind]
        lines = [f"clo:rt_{kind} a clo:ResourceType , owl:NamedIndividual ;",
                 f'    clo:resourceTypeName "{kind}" ;', f"    clo:implementsBaseKind clo:{bk} ;",
                 f"    clo:hostedBy clo:{prov} ;"]
        if ev:
            lines.append('    clo:labelingSupport "full" ;')
        c = (f"Extension type ({src}). Evidence: {ev} of {seen[kind]} recorded resources carry tags"
             + (" (E+)." if ev else " (E?, support left unknown).") + (f" {note}." if note else ""))
        lines.append(f'    rdfs:comment "{c}"@en .')
        out += lines + [""]
    open(a.out, "w").write("\n".join(out))
    for k in sorted(EXT):
        print(f"{k:36} seen={seen[k]:4} tagged={tagged[k]:4}")


if __name__ == "__main__":
    main()
