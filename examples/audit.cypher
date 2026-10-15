// Closed-world half of the CLO audit for Neo4j, after importing the
// HermiT-materialised graph with neosemantics (n10s) using
// handleVocabUris: "IGNORE" (local names as labels and relationship types).
// Same semantics as rules/cwa/I-07.rq, I-11.rq and I-19.rq. Not tested against a live
// Neo4j instance; the SPARQL rules are the reference implementation.

// I-07  missing required labels (complete records, in audit scope)
MATCH (r:AuditableResource)-[:governedBy]->(:LabelingPolicy)-[:requiresLabel]->(k:LabelKey)
WHERE r.recordComplete = true
  AND NOT EXISTS { (r)-[:hasLabel]->()-[:hasLabelKey]->(k) }
RETURN r.resourceId AS resource, k.keyName AS missing
ORDER BY resource, missing;

// I-11  unlabelled resources
MATCH (r:AuditableResource)
WHERE r.recordComplete = true AND NOT EXISTS { (r)-[:hasLabel]->() }
RETURN r.resourceId AS resource;

// I-19  'environment' coverage per BaseKind and provider
MATCH (r:AuditableResource)-[:hasBaseKind]->(bk), (r)-[:hostedBy]->(p)
WHERE r.recordComplete = true
WITH bk, p, count(r) AS n,
     count(CASE WHEN EXISTS {
       (r)-[:hasLabel]->()-[:hasLabelKey]->(:LabelKey {keyName: 'environment'})
     } THEN 1 END) AS covered
RETURN bk.uri AS kind, p.uri AS provider, n, covered, 100.0 * covered / n AS pct
ORDER BY kind, pct DESC;
