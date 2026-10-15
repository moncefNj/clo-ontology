#!/usr/bin/env python3
"""
test_org.py -- HermiT checks of the organisational module (clo_org.ttl, v9).

  pip install owlready2 rdflib     # Java 8+ required
  python3 tests/test_org.py        # from the repository root

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


TYPES = to_nt("types", os.path.join(HERE, "clo_types.ttl"))
EXT = to_nt("types_ext", os.path.join(HERE, "clo_types_ext.ttl"))
names = lambda xs: sorted(x.name for x in xs)

# ── Organisational module (clo_org.ttl) on the company example ─────────────
ORG = to_nt("org", os.path.join(HERE, "clo_org.ttl"))
COMPANY = to_nt("company", os.path.join(os.path.dirname(HERE), "examples", "company_example.ttl"))
w6 = ow.World()
for f in (TBOX, TYPES, EXT, ORG):
    w6.get_ontology("file://" + f).load()
o6 = w6.get_ontology("file://" + COMPANY).load()
check("T-Box + catalogue + org module + company example consistent", reason(w6, o6))
V = lambda n: w6.search_one(iri=CLO + n)
check("C-9: shared standard derived from role needs (4 keys)",
      names(V("pol_shared").requiresLabel) == ["k_cost_center", "k_data_class", "k_environment", "k_owner"])
check("C-10: Payments uses 'env' (observed convention)", "k_env" in names(V("team_payments").usesKey))
check("C-10: Platform does not use 'env'", "k_env" not in names(V("team_platform").usesKey))
check("C-11: team policy reaches owned resources", "pol_payments" in names(V("pay_db").governedBy))
check("C-4 + org root: shared policy reaches every account's resources",
      all("pol_shared" in names(V(r).governedBy) for r in ("pay_vm", "plat_gke", "data_sql", "orphan_vm")))
# v9: ownedBy is not functional. Two owners neither merge the teams nor make the
# knowledge base inconsistent; the conflict is the closed-world finding I-27.
w7 = ow.World()
for f in (TBOX, TYPES, ORG, COMPANY):
    w7.get_ontology("file://" + f).load()
o7 = w7.get_ontology("file://" + to_nt("twoowners", data=PFX + """<http://t/two> a owl:Ontology .
clo:pay_vm clo:ownedBy clo:team_platform .""")).load()
check("two owning teams: consistent", reason(w7, o7))
T7 = lambda n: w7.search_one(iri=CLO + n)
check("two owning teams: teams not merged (Payments does not inherit Platform's keys)",
      "k_managed_by" not in names(T7("team_payments").usesKey) and not T7("team_payments").equivalent_to)

print(f"\n{failures} failure(s)")
sys.exit(failures)
