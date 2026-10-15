#!/usr/bin/env python3
"""
audit.py -- the CLO pipeline in one file, without Neo4j.

1. Open-world half: HermiT (via Owlready2) classifies the inventory against
   the T-Box and the type catalogue (category, provider, BaseKind, audit
   scope, inherited policies).
2. Closed-world half: SPARQL queries with FILTER NOT EXISTS run over the
   materialised graph, restricted to complete records (clo:recordComplete).

  python3 audit.py                                  # the bundled example
  python3 audit.py --abox my_inventory.ttl          # your own inventory
"""
import argparse
import os
import tempfile

import owlready2 as ow
import rdflib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(os.path.dirname(HERE), "ontology")
CLO = "http://example.org/clo/ontology/clo#"
PREFIX = f"PREFIX clo: <{CLO}>\nPREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n"

QUERIES = {
    "UC1  classification (DL, inferred)": """
SELECT ?resource ?category ?provider ?kind (GROUP_CONCAT(?pol; separator=",") AS ?policies) WHERE {
  ?r a clo:CloudResource ; clo:resourceId ?resource ;
     clo:belongsToCategory ?c ; clo:hostedBy ?p ; clo:hasBaseKind ?k .
  OPTIONAL { ?r clo:governedBy ?g . BIND(STRAFTER(STR(?g), "#") AS ?pol) }
  BIND(STRAFTER(STR(?c), "#") AS ?category)
  BIND(STRAFTER(STR(?p), "#") AS ?provider)
  BIND(STRAFTER(STR(?k), "#") AS ?kind)
} GROUP BY ?resource ?category ?provider ?kind ORDER BY ?resource""",
    "UC2a I-07 missing required labels (CWA)": """
SELECT ?resource ?missing WHERE {
  ?r a clo:AuditableResource ; clo:recordComplete true ; clo:resourceId ?resource ;
     clo:governedBy ?pol .
  ?pol clo:requiresLabel ?key . ?key clo:keyName ?missing .
  FILTER NOT EXISTS { ?r clo:hasLabel/clo:hasLabelKey ?key }
} ORDER BY ?resource ?missing""",
    "UC2b I-11 unlabelled resources (CWA)": """
SELECT ?resource WHERE {
  ?r a clo:AuditableResource ; clo:recordComplete true ; clo:resourceId ?resource .
  FILTER NOT EXISTS { ?r clo:hasLabel ?l }
}""",
    "UC2c out of audit scope (I-05, inferred)": """
SELECT ?resource ?type WHERE {
  ?r a clo:CloudResource ; clo:resourceId ?resource ; clo:hasResourceType ?t .
  ?t a clo:UntaggableType ; clo:resourceTypeName ?type .
}""",
    "UC3  I-19 environment coverage per BaseKind and provider (CWA)": """
SELECT ?kind ?provider (COUNT(?r) AS ?n) (SUM(?has) AS ?covered) WHERE {
  ?r a clo:AuditableResource ; clo:hasBaseKind ?k ; clo:hostedBy ?p .
  BIND(IF(EXISTS { ?r clo:hasLabel/clo:hasLabelKey/clo:keyName "environment" }, 1, 0) AS ?has)
  BIND(STRAFTER(STR(?k), "#") AS ?kind) BIND(STRAFTER(STR(?p), "#") AS ?provider)
} GROUP BY ?kind ?provider ORDER BY ?kind ?provider""",
}


def to_nt(path, tmp):
    g = rdflib.Graph(); g.parse(path)
    out = os.path.join(tmp, os.path.basename(path) + ".nt")
    g.serialize(out, format="nt", encoding="utf-8")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--abox", default=os.path.join(HERE, "inventory_example.ttl"))
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        w = ow.World()
        for f in (os.path.join(ROOT, "clo_ontology_v8.ttl"), os.path.join(ROOT, "clo_types.ttl"), a.abox):
            last = w.get_ontology("file://" + to_nt(f, tmp)).load()
        with last:
            ow.sync_reasoner_hermit(w, infer_property_values=True, debug=0)
        g = w.as_rdflib_graph()
        for title, q in QUERIES.items():
            print(f"\n== {title}")
            for row in g.query(PREFIX + q):
                print("   " + "  ".join(str(v) for v in row))


if __name__ == "__main__":
    main()
