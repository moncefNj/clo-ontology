#!/usr/bin/env python3
"""
test_v8.py -- HermiT checks of every DL claim made about CLO v8 and its catalogue.

  pip install owlready2 rdflib     # Java 8+ required
  python3 tests/test_v8.py         # from the repository root

Each check prints PASS or FAIL; the exit code is the number of failures.
"""
import os
import sys
import tempfile

import owlready2 as ow
import rdflib

HERE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ontology")
CLO = "http://example.org/clo/ontology/clo#"
PFX = ("@prefix clo: <%s> . @prefix owl: <http://www.w3.org/2002/07/owl#> . "
       "@prefix xsd: <http://www.w3.org/2001/XMLSchema#> . "
       "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n" % CLO)
TMP = tempfile.mkdtemp()
failures = 0


def to_nt(name, path=None, data=None):
    g = rdflib.Graph()
    g.parse(path) if path else g.parse(data=data, format="turtle")
    out = os.path.join(TMP, name + ".nt")
    g.serialize(out, format="nt", encoding="utf-8")
    return out


TBOX = to_nt("tbox", os.path.join(HERE, "clo_ontology_v8.ttl"))
ABOX = to_nt("abox", os.path.join(HERE, "clo_test_abox.ttl"))


def world(extra=None):
    w = ow.World()
    w.get_ontology("file://" + TBOX).load()
    last = w.get_ontology("file://" + ABOX).load()
    if extra:
        last = w.get_ontology("file://" + to_nt(str(abs(hash(extra))),
                                                data=PFX + "<http://t/x> a owl:Ontology .\n" + extra)).load()
    return w, last


def reason(w, onto):
    try:
        with onto:
            ow.sync_reasoner_hermit(w, infer_property_values=True, debug=0)
        return True
    except ow.OwlReadyInconsistentOntologyError:
        return False


def check(label, ok):
    global failures
    print(("PASS " if ok else "FAIL ") + label)
    failures += not ok


w, a = reason_world = world()
check("T-Box + test A-Box consistent", reason(w, a))
X = lambda n: w.search_one(iri=CLO + n)
names = lambda xs: sorted(x.name for x in xs)
inst = lambda c: names(X(c).instances(world=w))

check("I-01 category via C-2 (ec2 -> Compute)", names(X("res_test_ec2_01").belongsToCategory) == ["Compute"])
check("I-01 defined class (ec2 is ComputeResource)", X("ComputeResource") in X("res_test_ec2_01").is_a)
check("I-02 provider via C-1 (k8s pod -> Kubernetes)", names(X("res_test_k8s_01").hostedBy) == ["Kubernetes"])
check("I-03 category policy via C-5 (GCE gets compute policy)", "test_compute_policy" in names(X("res_test_gce_01").governedBy))
check("I-03 not applied outside category (S3)", "test_compute_policy" not in names(X("res_test_s3_01").governedBy))
check("I-04 base kind via C-6", names(X("res_test_gce_01").hasBaseKind) == ["InstanceKind"])
check("I-04 cross-provider types via C-7", {"rt_gcp_instance", "rt_kubernetes_pod"} <= set(names(X("rt_aws_ec2_instance").sameBaseKindAs)))
check("I-05 GitHub team out of audit scope", "res_test_gh_team" not in inst("AuditableResource"))
check("I-05 S3 bucket in audit scope", "res_test_s3_01" in inst("AuditableResource"))
check("I-08 LabeledResource populated", "res_test_ec2_01" in inst("LabeledResource"))
check("I-10 policy via partOf (C-3)", "test_compute_policy" in names(X("res_test_ec2_child").governedBy))
check("I-10b policy via OU (C-4)", "test_ou_policy" in names(X("res_test_ou_member").governedBy))
check("I-10b policy via account (C-8)", "test_account_policy" in names(X("res_test_s3_01").governedBy))
check("I-11 NOT inferred from absence (S3 bucket)", "res_test_s3_01" not in inst("UnlabeledResource"))
check("I-11 inferred under explicit closure", inst("UnlabeledResource") == ["res_test_closed"])
check("Critical is a NonCompliant", "res_test_closed" in inst("NonCompliant"))

cases = {
    "two types, different categories -> inconsistent":
        (False, "clo:x a clo:CloudResource , owl:NamedIndividual ; clo:hasResourceType clo:rt_aws_ec2_instance , clo:rt_aws_s3_bucket ."),
    "two types, same category -> NOT detected":
        (True, "clo:x a clo:CloudResource , owl:NamedIndividual ; clo:hasResourceType clo:rt_aws_ec2_instance , clo:rt_gcp_instance ."),
    "two providers -> NOT detected (hostedBy non-simple)":
        (True, "clo:x a clo:CloudResource , owl:NamedIndividual ; clo:hostedBy clo:AWS , clo:GCP ."),
}
for label, (expect_consistent, body) in cases.items():
    w2, o2 = world(body)
    check(label, reason(w2, o2) == expect_consistent)

facet = """clo:LongKey owl:equivalentClass [ a owl:Class ; owl:intersectionOf ( clo:LabelKey
  [ a owl:Restriction ; owl:onProperty clo:keyName ; owl:someValuesFrom [ a rdfs:Datatype ;
    owl:onDatatype xsd:string ; owl:withRestrictions ( [ xsd:minLength 64 ] ) ] ] ) ] .
clo:UpperKey owl:equivalentClass [ a owl:Class ; owl:intersectionOf ( clo:LabelKey
  [ a owl:Restriction ; owl:onProperty clo:keyName ; owl:someValuesFrom [ a rdfs:Datatype ;
    owl:onDatatype xsd:string ; owl:withRestrictions ( [ xsd:pattern ".*[A-Z].*" ] ) ] ] ) ] .
clo:k1 a clo:LabelKey , owl:NamedIndividual ; clo:keyName "%s" .
clo:k2 a clo:LabelKey , owl:NamedIndividual ; clo:keyName "CostCenter" .
clo:k3 a clo:LabelKey , owl:NamedIndividual ; clo:keyName "env" .""" % ("a" * 70)
w3, o3 = world(facet)
reason(w3, o3)
Y = lambda n: w3.search_one(iri=CLO + n)
check("I-14 expressible in DL (minLength facet)", names(Y("LongKey").instances(world=w3)) == ["k1"])
check("I-13 expressible in DL (pattern facet)", names(Y("UpperKey").instances(world=w3)) == ["k2"])

# ── Type catalogue (clo_types.ttl) ──────────────────────────────────────────
TYPES = to_nt("types", os.path.join(HERE, "clo_types.ttl"))
w4 = ow.World()
w4.get_ontology("file://" + TBOX).load()
o4 = w4.get_ontology("file://" + TYPES).load()
check("T-Box + type catalogue consistent", reason(w4, o4))
Z = lambda n: w4.search_one(iri=CLO + n)
check("catalogue: aws_iam_group is UntaggableType (curated)", Z("UntaggableType") in Z("rt_aws_iam_group").is_a)
check("catalogue: types are not re-typed as CloudResource",
      not any(Z("CloudResource") in t.is_a for t in Z("ResourceType").instances(world=w4)))
w5, o5 = world("clo:bad a clo:CloudResource , clo:ResourceType , owl:NamedIndividual .")
check("guard V8-13: resource typed as ResourceType -> inconsistent", not reason(w5, o5))

print(f"\n{failures} failure(s)")
sys.exit(failures)
