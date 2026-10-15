"""
clo.kb -- load CLO, materialise the open-world inferences with one of four
engines, and extract the operative entailment set E for comparison.

Engines
  clo-r   the rule set rules/materialise.ru applied to a fixpoint in Oxigraph
          (equality-free OWL 2 RL fragment; the run-time default)
  owlrl   the OWL 2 RL/RDF rules of the W3C profile, owlrl package (pure Python)
  hermit  HermiT 1.3.8 through Owlready2 (OWL 2 DL; design-time engine)
  pellet  Pellet 2 through Owlready2 (OWL 2 DL). Owlready2 0.51 bundles a Jena
          built for Java 25; with an older JVM set CLO_PELLET_PYTHON to a Python
          with Owlready2 0.46 (see requirements-pellet.txt).

E is the set of operative entailments of Table 2: class assertions to the
category classes, AuditableResource, LabeledResource and the three
labelling-support classes, and the property assertions hostedBy (resources),
belongsToCategory, hasBaseKind, sameBaseKindAs, governedBy, requiresLabel, usesKey.
"""
import os
import subprocess
import sys
import tempfile
import time

import pyoxigraph as ox
import rdflib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLO = "http://example.org/clo/ontology/clo#"
ONTO = os.path.join(ROOT, "ontology")
TBOX_FILES = ["clo_ontology_v8.ttl", "clo_types.ttl", "clo_types_ext.ttl", "clo_org.ttl"]
RULES = os.path.join(ROOT, "rules", "materialise.ru")

OPERATIVE_CLASSES = [CLO + c for c in (
    "ComputeResource StorageResource NetworkingResource DatabaseResource SecurityResource MessagingResource "
    "GovernanceResource MonitoringResource AIMLResource AnalyticsResource ContainerResource IdentityResource "
    "SecretResource AuditableResource LabeledResource FullyTaggableType PartiallyTaggableType UntaggableType").split()]
OPERATIVE_PROPS = [CLO + p for p in
                   "hostedBy belongsToCategory hasBaseKind sameBaseKindAs governedBy requiresLabel usesKey".split()]

E_QUERY = """PREFIX clo: <%s>
SELECT ?s ?p ?o WHERE {
  { ?s a ?o . VALUES ?o { %s } BIND(<http://www.w3.org/1999/02/22-rdf-syntax-ns#type> AS ?p)
    { ?s a clo:CloudResource } UNION { ?s a clo:ResourceType } }
  UNION
  { ?s ?p ?o . VALUES ?p { %s } FILTER(isIRI(?o))
    { ?s a clo:CloudResource } UNION { ?s a clo:ResourceType } UNION { ?s a clo:LabelingPolicy } UNION { ?s a clo:Team } }
}""" % (CLO, " ".join(f"<{c}>" for c in OPERATIVE_CLASSES), " ".join(f"<{p}>" for p in OPERATIVE_PROPS))


def tbox_paths(extra=()):
    return [os.path.join(ONTO, f) for f in TBOX_FILES if os.path.exists(os.path.join(ONTO, f))] + list(extra)


def load_store(paths):
    st = ox.Store()
    for p in paths:
        fmt = ox.RdfFormat.N_TRIPLES if p.endswith(".nt") else ox.RdfFormat.TURTLE
        st.bulk_load(path=p, format=fmt)
    return st


def materialise_clo_r(store, max_rounds=50):
    """Apply rules/materialise.ru to a fixpoint. Returns the number of rounds."""
    text = open(RULES).read()
    prefix = "\n".join(l for l in text.splitlines() if l.startswith("PREFIX"))
    body = "\n".join(l for l in text.splitlines() if not l.startswith("PREFIX") and not l.lstrip().startswith("#"))
    stmts = [prefix + "\n" + s.strip() for s in body.split(";\n") if s.strip()]
    n = len(store)
    for rnd in range(1, max_rounds + 1):
        for s in stmts:
            store.update(s)
        m = len(store)
        if m == n:
            return rnd
        n = m
    raise RuntimeError("no fixpoint")


def entailments_store(store):
    return {(str(s.value), str(p.value), str(o.value)) for s, p, o in
            ((b["s"], b["p"], b["o"]) for b in store.query(E_QUERY))}


def entailments_rdflib(g):
    return {(str(s), str(p), str(o)) for s, p, o in g.query(E_QUERY)}


def run_clo_r(abox_paths):
    t0 = time.perf_counter()
    st = load_store(tbox_paths(abox_paths))
    t1 = time.perf_counter()
    rounds = materialise_clo_r(st)
    t2 = time.perf_counter()
    return st, {"load_s": t1 - t0, "reason_s": t2 - t1, "rounds": rounds}


def run_owlrl(abox_paths):
    import owlrl
    t0 = time.perf_counter()
    g = rdflib.Graph()
    for p in tbox_paths(abox_paths):
        g.parse(p)
    t1 = time.perf_counter()
    owlrl.DeductiveClosure(owlrl.OWLRL_Semantics, axiomatic_triples=False,
                           datatype_axioms=False).expand(g)
    t2 = time.perf_counter()
    return g, {"load_s": t1 - t0, "reason_s": t2 - t1}


_OWLREADY_CHILD = r'''
import json, sys, time, owlready2 as ow, rdflib
engine, out = sys.argv[1], sys.argv[2]
w = ow.World()
last = None
for p in sys.argv[3:]:
    last = w.get_ontology("file://" + p).load()
t0 = time.perf_counter()
status = "ok"
try:
    with last:
        if engine == "hermit":
            ow.sync_reasoner_hermit(w, infer_property_values=True, debug=0)
        else:
            ow.sync_reasoner_pellet(w, infer_property_values=True, infer_data_property_values=False, debug=0)
except ow.OwlReadyInconsistentOntologyError:
    status = "inconsistent"
t1 = time.perf_counter()
w.as_rdflib_graph().serialize(out, format="nt", encoding="utf-8")
print(json.dumps({"reason_s": t1 - t0, "status": status}))
'''


def to_nt(paths, tmp):
    """Owlready2 needs one ontology per file; N-Triples parses fastest."""
    outs = []
    for i, p in enumerate(paths):
        g = rdflib.Graph()
        g.parse(p, format="nt" if p.endswith(".nt") else "turtle")
        o = os.path.join(tmp, f"{i:02d}_{os.path.basename(p)}.nt")
        if not any(True for _ in g.triples((None, rdflib.RDF.type, rdflib.OWL.Ontology))):
            g.add((rdflib.URIRef(f"http://example.org/clo/tmp/onto{i}"), rdflib.RDF.type, rdflib.OWL.Ontology))
        g.serialize(o, format="nt", encoding="utf-8")
        outs.append(o)
    return outs


def run_owlready(engine, abox_paths, timeout=None):
    import json
    with tempfile.TemporaryDirectory() as tmp:
        nts = to_nt(tbox_paths(abox_paths), tmp)
        out = os.path.join(tmp, "out.nt")
        t0 = time.perf_counter()
        py = os.environ.get("CLO_PELLET_PYTHON", sys.executable) if engine == "pellet" else sys.executable
        proc = subprocess.Popen([py, "-I", "-c", _OWLREADY_CHILD, engine, out] + nts, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, 9)          # the reasoner's JVM is in the same process group
            proc.communicate()
            return None, {"status": "timeout", "reason_s": timeout, "wall_s": timeout}
        p = subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
        if p.returncode:
            return None, {"status": "error", "stderr": p.stderr[-1500:]}
        info = json.loads(p.stdout.strip().splitlines()[-1])
        info["wall_s"] = time.perf_counter() - t0
        g = rdflib.Graph()
        g.parse(out, format="nt")
        return g, info


def materialise(engine, abox_paths, timeout=None):
    """Returns (queryable graph or store, info). Use entailments() on the result."""
    if engine == "clo-r":
        return run_clo_r(abox_paths)
    if engine == "owlrl":
        return run_owlrl(abox_paths)
    if engine in ("hermit", "pellet"):
        return run_owlready(engine, abox_paths, timeout)
    raise ValueError(engine)


def entailments(kb):
    return entailments_store(kb) if isinstance(kb, ox.Store) else entailments_rdflib(kb)


def as_store(kb):
    """Closed-world rules always run in Oxigraph, over the materialised graph."""
    if isinstance(kb, ox.Store):
        return kb
    st = ox.Store()
    with tempfile.NamedTemporaryFile(suffix=".nt", delete=False) as f:
        path = f.name
    kb.serialize(path, format="nt", encoding="utf-8")
    st.bulk_load(path=path, format=ox.RdfFormat.N_TRIPLES)
    os.unlink(path)
    return st
