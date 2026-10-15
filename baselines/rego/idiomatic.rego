# B2a -- policy-as-code as commonly written: one data-driven list of required keys per
# scope (company, OU, account, resource-type list), exact key match, evaluated over an
# inventory export. Cross-provider equivalence is a literal list of type names.
package tagging.idiomatic

import rego.v1

shared_keys := {k | some k in data.cfg.shared}

ou_keys(r) := {k | some k in object.get(data.cfg.ou, r.ou, [])}

account_keys(r) := {k | some k in object.get(data.cfg.account, r.account, [])}

type_keys(r) := {k |
	types := data.cfg.by_type[k]
	r.type in types
}

required(r) := union({shared_keys, ou_keys(r), account_keys(r), type_keys(r)})

violation contains [r.id, k] if {
	some r in input.resources
	r.type in data.cfg.taggable_types
	some k in required(r)
	not k in object.keys(r.tags)
}
