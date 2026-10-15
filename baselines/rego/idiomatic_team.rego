# B2b -- the idiomatic data-driven policy of idiomatic.rego, extended by a practitioner with
# team scope: the inventory export carries the owning teams, and data.cfg.team lists the
# keys each team's policy requires. Still exact key match, no synonyms, no composition,
# no record completeness.
package tagging.idiomatic_team

import rego.v1

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

required(r) := union({shared_keys, ou_keys(r), account_keys(r), type_keys(r), team_keys(r)})

violation contains [r.id, k] if {
	some r in input.resources
	some t in r.types
	t in data.cfg.taggable_types
	some k in required(r)
	not k in object.keys(r.tags)
}
