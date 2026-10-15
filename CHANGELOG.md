# Changelog

## 9.2 — 2026-10

- Competency questions CQ1–CQ6 (`examples/cq/`, `tools/run_cqs.py`, `tests/test_cq.py`).
- Ontology reference and metrics (`tools/onto_doc.py` → `docs/ontology.md`, `docs/metrics.json`).
- CLO Studio video (`tools/record_demo_video.py` → `demo/clo_studio_demo.mp4`) and a `Dockerfile`.

## 9.1 — 2026-10

Evaluation
- RQ1: planted defects are matched to findings per (resource, key) without the oracle, and every miss is
  classified (key not required, truncated record, out of scope, overwritten, spelling outside the synonym
  groups). The 9.0 count used the oracle to decide applicability and CLO's own I-25 output to decide detection.
- RQ1: the oracle now also covers I-19 (coverage) and I-21 (value on a parent).
- RQ2: `tools/validate_completeness.py`, a witness check of the completeness rules on the fixtures;
  tag-derived ownership is declared (`clo:ownershipFromKey`) so a missing owner key and I-26 are one root cause;
  coverage of top-level records; distinct unmanaged keys.
- RQ3: OPA with team scope, AWS Config + Azure Policy + GCP custom constraints, and a second, "flat" ground
  truth without team policies and composition, so recall separates detection from expressiveness.
- RQ4: `eval/e2e_scale.py`, the end-to-end cost of a cycle.
- RQ5: `eval/repair_sensitivity.py` breaks the generator's regularities (`gen_corpus.build(..., violate=v)`,
  separate random stream, v=0 reproduces 9.0 exactly) and adds a practitioner heuristic ("majority" policy).

Fixes
- I-07 and I-21 use MINUS instead of FILTER NOT EXISTS: same answers, but Oxigraph evaluated NOT EXISTS per
  solution and the audit grew quadratically (34 s → 3 s at 4,000 resources).
- `eval/loop.py` used Python's salted `hash()` for the true carbon scope, so the loop was not reproducible
  across processes; now SHA-256.
- `baselines/run_baselines.py` finds `custodian` on PATH.

Tools
- **CLO Studio** (`tools/clo_demo.py`, `make demo`): the interactive demonstrator.

Anonymisation
- Namespace moved to `http://example.org/clo/...` for review; header comments and the 182 `@fr`
  annotations removed from the T-Box (English annotations kept); `dc:creator` anonymised.

## 9.0 — 2026-10

Reasoning and correctness
- **CLO-R** (`rules/materialise.ru`): the operative open-world inferences as 19 equality-free
  SPARQL rules, run to a fixpoint in Oxigraph; same operative entailments as HermiT and Pellet
  wherever they finish (company example, synthetic estates up to 1,000 resources, open corpus).
- `ownedBy` is **no longer functional**: with no unique-name assumption, two owners made HermiT
  merge the two teams. New closed-world rules I-27 (several owners) and I-28 (several types).
- All closed-world rules released (`rules/cwa/`, plus I-12, I-18, I-20 in `clo/audit.py`);
  I-19 now respects `recordComplete`; I-15 exempts prefixes of container orchestrators.
- Root-cause grouping (an unlabelled resource is one finding), role attribution through the
  governing policies, coverage denominators per role.
- Variants: declared synonyms, and case/separator variants of synonyms and managed keys.
- Fixed during development, found by the differential test against eval/oracle.py: I-14 and I-15
  used variables inside UNION branches that are bound outside them (SPARQL evaluates groups
  bottom-up), so they never fired; provider identification relied on an rdf:type that CLO-R does
  not derive (subclass of InfraProvider). Found on the open corpus: I-15 flagged four EKS-written
  kubernetes.io/ keys on AWS subnets (kubernetes.io/role/elb, kubernetes.io/role/internal-elb,
  kubernetes.io/cluster/test, kubernetes.io/cluster/test2); prefixes of container orchestrators are now exempt.

Repairs and execution
- `clo:valueSource` per key (`inherit`, `account-default`, `team-default`); dominance threshold
  for defaults; `data-classification` is never guessed.
- `tools/clo_compile.py`: AWS Config REQUIRED_TAGS rules, Azure Policy assignments, Cloud
  Custodian policies, dry-run repair commands.

Data and evaluation
- `tools/ingest_c7n.py`: inventory from Cloud Custodian's recorded AWS/Azure/GCP responses, with
  record completeness derived from the response shape; 10 catalogue types added with
  evidence-based labelling support.
- Released generator with true values and planted defects, independent oracle, baselines
  (AWS Config + Azure Policy, Cloud Custodian, two OPA policies), engine comparison, loop
  simulation, and `eval/make_tables.py` generating every paper number.
- The 8.x HermiT batching tools moved to `tools/legacy_v8/`.

## 8.1 — 2026-10

- **Organisational module** `ontology/clo_org.ttl`: `Team`, `GovernanceRole`
  (FinOps, Security, Operations, Development, Platform engineering),
  `ownedBy` (functional), `playsRole`, `needsLabel`, `servesRole`, `usesKey`;
  chains C-9 (shared standard derived from role needs), C-10 (keys a team
  uses), C-11 (team policies). In the OWL 2 DL profile with the T-Box.
- **Diagnosis-and-repair cycle** `tools/clo_audit.py` and **explorer**
  `tools/clo_viz.py`; worked company example in `examples/`.
- Tests: `tests/test_org.py` (7 HermiT checks) next to `tests/test_v8.py` (26).

## 8.0 — 2026-10

Every change was checked with HermiT; see `tests/test_v8.py` (26 checks).

- **Inferences made operative.** I-03 default policy per category (chain
  C-5), I-04 cross-provider equivalence (C-6 `hasBaseKind`, C-7
  `sameBaseKindAs`), I-05 audit scope (`FullyTaggableType`,
  `PartiallyTaggableType`, `UntaggableType`, `AuditableResource`), I-10b
  account policies (C-8).
- **Type catalogue** `clo_types.ttl`: 165 Fix Inventory resource types mapped
  to BaseKinds, with labelling support curated from provider documentation
  (`data/labeling_support_curated.csv`).
- **Semantics.** `CriticalNonCompliant ⊑ NonCompliant`; `UnlabeledResource`
  and `FullyCompliantResource` annotated `clo:operative false` (they cannot
  fire under OWA without a closure axiom); `clo:recordComplete` for local
  closed-world checks; `CloudResource` disjoint from `ResourceType`;
  `owl:AllDifferent` over providers and categories.
- **Provider constraints.** Kubernetes keys may contain upper case; reserved
  prefixes `k8s.io/`, `google-`, `microsoft`, `azure`, `windows`.
- **OWL 2 DL compliance.** SKOS and Dublin Core entities declared (v7 had 20
  profile violations; v8 has none). Ontology IRI
  `http://example.org/clo/ontology/clo`, `owl:versionIRI`, `dcterms:license`.
- **Documentation.** English `rdfs:comment` on all 182 commented entities;
  English `rdfs:label` on all 192 CLO entities.
- Test A-Box moved to `clo_test_abox.ttl`.

## 7.0

Previous release (single file with an embedded test A-Box).
