# CLO-R: the run-time materialisation of CLO's operative open-world inferences.
#
# Each INSERT below is the rule form of one T-Box axiom of clo_ontology_v8.ttl or
# clo_org.ttl (cited at the end of the line). Every rule is an entailment of the
# T-Box (soundness), and together they cover the operative inference set E of
# Table 2 (checked against HermiT and Pellet by eval/engines.py). The rule set is
# equality-free: functional properties, owl:hasKey and owl:sameAs are never used
# to merge individuals at run time; conflicting assertions are reported by the
# closed-world rules I-27/I-28 instead.
#
# Applied to a fixpoint by clo/kb.py (pyoxigraph). Statements are separated by ';'.
PREFIX clo: <http://example.org/clo/ontology/clo#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

# transitivity (partOf, orgPartOf: owl:TransitiveProperty)
INSERT { ?a clo:partOf ?c } WHERE { ?a clo:partOf ?b . ?b clo:partOf ?c } ;
INSERT { ?a clo:orgPartOf ?c } WHERE { ?a clo:orgPartOf ?b . ?b clo:orgPartOf ?c } ;
# C-1 provider (I-02)
INSERT { ?r clo:hostedBy ?p } WHERE { ?r clo:hasResourceType ?t . ?t clo:hostedBy ?p } ;
# C-6 BaseKind (I-04, resource level)
INSERT { ?r clo:hasBaseKind ?k } WHERE { ?r clo:hasResourceType ?t . ?t clo:implementsBaseKind ?k } ;
# C-7 cross-provider type equivalence (I-04)
INSERT { ?t clo:sameBaseKindAs ?u } WHERE { ?t clo:implementsBaseKind ?k . ?u clo:implementsBaseKind ?k } ;
# C-2 category (I-01)
INSERT { ?r clo:belongsToCategory ?c } WHERE { ?r clo:hasResourceType ?t . ?t clo:implementsBaseKind ?k . ?k clo:categoryOf ?c } ;
# category classes, e.g. ComputeResource == belongsToCategory value Compute (I-01)
INSERT { ?r a ?cls } WHERE {
  ?r clo:belongsToCategory ?c .
  VALUES (?c ?cls) {
    (clo:Compute clo:ComputeResource) (clo:Storage clo:StorageResource) (clo:Networking clo:NetworkingResource)
    (clo:Database clo:DatabaseResource) (clo:Security clo:SecurityResource) (clo:Messaging clo:MessagingResource)
    (clo:Governance clo:GovernanceResource) (clo:Monitoring clo:MonitoringResource) (clo:AIML clo:AIMLResource)
    (clo:Analytics clo:AnalyticsResource) (clo:Container clo:ContainerResource) (clo:Identity clo:IdentityResource)
    (clo:Secret clo:SecretResource) } } ;
# D-6..D-8 labelling support of types (I-05)
INSERT { ?t a clo:FullyTaggableType } WHERE { ?t a clo:ResourceType ; clo:labelingSupport "full" } ;
INSERT { ?t a clo:PartiallyTaggableType } WHERE { ?t a clo:ResourceType ; clo:labelingSupport "partial" } ;
INSERT { ?t a clo:UntaggableType } WHERE { ?t a clo:ResourceType ; clo:labelingSupport "none" } ;
# D-9 audit scope (I-05)
INSERT { ?r a clo:AuditableResource } WHERE {
  ?r a clo:CloudResource ; clo:hasResourceType ?t .
  { ?t a clo:FullyTaggableType } UNION { ?t a clo:PartiallyTaggableType } } ;
# D-2 labelled resource (I-08)
INSERT { ?r a clo:LabeledResource } WHERE { ?r clo:hasLabel ?l } ;
# C-9 required keys derived from role needs (I-23)
INSERT { ?pol clo:requiresLabel ?k } WHERE { ?pol clo:servesRole ?ro . ?ro clo:needsLabel ?k } ;
# C-10 keys a team uses (I-24)
INSERT { ?t clo:usesKey ?k } WHERE { ?r clo:ownedBy ?t ; clo:hasLabel ?l . ?l clo:hasLabelKey ?k } ;
# C-5 category policy (I-03)
INSERT { ?r clo:governedBy ?pol } WHERE { ?r clo:belongsToCategory ?c . ?pol clo:appliesToCategory ?c } ;
# C-8 account policy (I-10b)
INSERT { ?r clo:governedBy ?pol } WHERE { ?r clo:belongsToAccount ?a . ?a clo:governedBy ?pol } ;
# C-4 organisational hierarchy (I-10b)
INSERT { ?r clo:governedBy ?pol } WHERE { ?r clo:belongsToAccount ?a . ?a clo:orgPartOf ?u . ?u clo:governedBy ?pol } ;
# C-11 team policy (I-10c)
INSERT { ?r clo:governedBy ?pol } WHERE { ?r clo:ownedBy ?t . ?t clo:governedBy ?pol } ;
# C-3 composition (I-10)
INSERT { ?r clo:governedBy ?pol } WHERE { ?r clo:partOf ?p . ?p clo:governedBy ?pol }
