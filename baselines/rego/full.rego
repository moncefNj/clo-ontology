# B2b -- the same semantics as CLO's I-07/I-11/I-22/I-26 re-implemented in Rego:
# team policies (C-11), composition inheritance (C-3), record completeness (local
# closed world), declared synonyms and case/separator variants (I-22), unlabelled
# resources (I-11) and resources without an owner (I-26).
package tagging.full

import rego.v1

parents[r.id] := {r.parent} if {
	some r in input.resources
	r.parent != null
}

parents[r.id] := set() if {
	some r in input.resources
	r.parent == null
}

ancestors(id) := graph.reachable(parents, {id}) - {id}

by_id[r.id] := r if some r in input.resources

shared_keys := {k | some k in data.cfg.shared}

ou_keys(r) := {k | some k in object.get(data.cfg.ou, r.ou, [])}

account_keys(r) := {k | some k in object.get(data.cfg.account, r.account, [])}

type_keys(r) := {k |
	types := data.cfg.by_type[k]
	some t in r.types
	t in types
}

team_keys(r) := {k |
	some t in r.owners
	some k in object.get(data.cfg.team, t, [])
}

own_keys(r) := union({shared_keys, ou_keys(r), account_keys(r), type_keys(r), team_keys(r)})

inherited_keys(r) := {k |
	some a in ancestors(r.id)
	some k in own_keys(by_id[a])
}

required(r) := own_keys(r) | inherited_keys(r)

norm(s) := regex.replace(lower(s), `[-_ .:/]`, "")

managed := {k | some k in data.cfg.managed}

system(name) if {
	some p in data.cfg.reserved
	startswith(lower(name), p)
}

variant_of(name) := c if {
	not system(name)
	syns := data.cfg.synonyms[c]
	name in syns
}

variant_of(name) := c if {
	not system(name)
	not declared_synonym(name)
	syns := data.cfg.synonyms[c]
	some s in array.concat(syns, [c])
	norm(s) == norm(name)
	c != name
}

variant_of(name) := m if {
	not system(name)
	not declared_synonym(name)
	not normalised_synonym(name)
	some m in managed
	norm(m) == norm(name)
	m != name
}

normalised_synonym(name) if {
	syns := data.cfg.synonyms[c]
	some s in array.concat(syns, [c])
	norm(s) == norm(name)
}

declared_synonym(name) if {
	some syns in data.cfg.synonyms
	name in syns
}

in_scope(r) if {
	some t in r.types
	t in data.cfg.taggable_types
}

missing contains [r.id, k] if {
	some r in input.resources
	in_scope(r)
	r.complete
	count(r.tags) > 0
	some k in required(r)
	not k in object.keys(r.tags)
}

rename contains [r.id, k] if {
	some [id, k] in missing
	r := by_id[id]
	some used in object.keys(r.tags)
	variant_of(used) == k
}

unlabelled contains r.id if {
	some r in input.resources
	in_scope(r)
	r.complete
	count(r.tags) == 0
}

no_owner contains r.id if {
	some r in input.resources
	in_scope(r)
	r.complete
	count(r.owners) == 0
}

# (resource, key) pairs, unlabelled resources expanded to their required keys
violation contains p if some p in missing

violation contains [id, k] if {
	some id in unlabelled
	some k in required(by_id[id])
}
