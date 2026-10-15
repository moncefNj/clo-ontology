"""
clo.audit -- the closed-world half of the cycle: run the CWA rules of
rules/cwa/ over a materialised graph, group findings by root cause, attribute
them to the roles of the governing policy, and plan repairs.

Rule semantics are stated in the header of each rules/cwa/I-xx.rq file; the
rules that need computation SPARQL cannot express (edit distance, thresholds,
key normalisation) are implemented here and marked [py].
"""
import collections
import os
import re

from . import kb

CLO = kb.CLO
RULE_DIR = os.path.join(kb.ROOT, "rules", "cwa")
PREFIX = open(os.path.join(RULE_DIR, "_prefix.rq")).read()

ERROR, WARNING, INFO = "error", "warning", "info"
SEVERITY = {"I-07": ERROR, "I-09": ERROR, "I-11": ERROR, "I-13": ERROR, "I-14": ERROR, "I-15": ERROR,
            "I-16": ERROR, "I-22": ERROR, "I-26": ERROR, "I-27": ERROR, "I-28": ERROR,
            "I-22r": WARNING, "I-12": WARNING, "I-17": INFO, "I-20": INFO, "I-25": INFO, "I-19": INFO}
# thresholds (stated in the paper)
TEAM_DEFAULT_SHARE = 0.8      # I-18: a team value is proposed only if it covers >= 80 % of the team's uses
TEAM_DEFAULT_MIN = 2          #       ... of at least two resources
ENV_AT_RISK = 0.2             # I-12: share of an environment's resources with an error finding (T-Box default, AtRisk)
COVERAGE_GAP = 20.0           # I-19: percentage-point gap between providers for one BaseKind
EDIT_DISTANCE = 2             # I-20


def norm(name):
    """Key normalisation for variant detection: case and separators are not significant.
    A key is a variant of canonical key c if it is a declared member of c's synonym group,
    or equal to a member of that group or to a managed key after normalisation."""
    return re.sub(r"[-_ .:/]", "", name.lower())


def lev(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _q(store, text):
    res = store.query(PREFIX + text)
    names = [v.value for v in res.variables]
    for row in res:
        yield {n: (row[n].value if row[n] is not None else None) for n in names}


def rule(store, rid, **subst):
    text = open(os.path.join(RULE_DIR, rid + ".rq")).read()
    for k, v in subst.items():
        text = text.replace("?" + k, v)
    return list(_q(store, text))


def loc(iri):
    return iri.split("#")[-1] if iri else iri


class Audit:
    def __init__(self, store, repair_policy="safe"):
        self.st = store
        self.repair_policy = repair_policy
        self._context()

    # ── context read once from the graph ──────────────────────────────────────
    def _context(self):
        st = self.st
        self.keyname = {r["k"]: r["n"] for r in _q(st, "SELECT ?k ?n WHERE { ?k a clo:LabelKey ; clo:keyName ?n }")}
        self.resources = {r["r"]: r for r in _q(st, """SELECT ?r ?id ?type ?prov ?cat ?complete ?scope WHERE {
            ?r a clo:CloudResource . OPTIONAL { ?r clo:resourceId ?id }
            OPTIONAL { ?r clo:hasResourceType/clo:resourceTypeName ?type }
            OPTIONAL { ?r clo:hostedBy ?prov . ?prov clo:providerName ?pn }
            OPTIONAL { ?r clo:belongsToCategory ?cat }
            OPTIONAL { ?r clo:recordComplete ?complete }
            BIND(EXISTS { ?r a clo:AuditableResource } AS ?scope) }""")}
        self.labels = collections.defaultdict(dict)       # r -> {key iri: value}
        for row in _q(st, """SELECT ?r ?k ?v WHERE { ?r clo:hasLabel ?l . ?l clo:hasLabelKey ?k .
                             OPTIONAL { ?l clo:hasLabelValue/clo:valueName ?v } }"""):
            self.labels[row["r"]][row["k"]] = row["v"]
        self.owner = collections.defaultdict(set)
        for row in _q(st, "SELECT ?r ?t WHERE { ?r clo:ownedBy ?t }"):
            self.owner[row["r"]].add(row["t"])
        self.team_label = {r["t"]: r["n"] for r in _q(st, "SELECT ?t ?n WHERE { ?t a clo:Team ; rdfs:label ?n }")}
        self.account = collections.defaultdict(set)
        for row in _q(st, "SELECT ?r ?a WHERE { ?r a clo:CloudResource ; clo:belongsToAccount ?a }"):
            self.account[row["r"]].add(row["a"])
        self.parent = collections.defaultdict(set)
        for row in _q(st, "SELECT ?r ?p WHERE { ?r clo:partOf ?p }"):
            self.parent[row["r"]].add(row["p"])
        self.policy_roles = collections.defaultdict(set)   # (pol, key) -> roles
        for row in _q(st, """SELECT ?pol ?k ?role WHERE { ?pol clo:servesRole ?ro . ?ro clo:needsLabel ?k ;
                             rdfs:label ?role }"""):
            self.policy_roles[(row["pol"], row["k"])].add(row["role"])
        self.gov = collections.defaultdict(set)
        for row in _q(st, "SELECT ?r ?p WHERE { ?r a clo:CloudResource ; clo:governedBy ?p }"):
            self.gov[row["r"]].add(row["p"])
        self.pol_req = collections.defaultdict(set)
        for row in _q(st, "SELECT ?p ?k WHERE { ?p clo:requiresLabel ?k }"):
            self.pol_req[row["p"]].add(row["k"])
        self.policy_label = {r["p"]: r["n"] for r in _q(st, "SELECT ?p ?n WHERE { ?p a clo:LabelingPolicy ; rdfs:label ?n }")}
        self.required = {r["k"] for r in _q(st, "SELECT DISTINCT ?k WHERE { ?p clo:requiresLabel ?k }")}
        self.needed = {r["k"] for r in _q(st, "SELECT DISTINCT ?k WHERE { ?ro clo:needsLabel ?k }")}
        self.canon = {}                                     # synonym member key iri -> canonical name
        for row in _q(st, "SELECT ?m ?c WHERE { ?g clo:hasMember ?m ; clo:canonicalKey ?c }"):
            self.canon[row["m"]] = row["c"]
        self.vocab_keys = {r["k"] for r in _q(st, "SELECT DISTINCT ?k WHERE { ?k clo:hasVocabulary ?v }")}
        self.allowed = collections.defaultdict(set)
        for row in _q(st, "SELECT ?k ?v WHERE { ?k clo:hasVocabulary/clo:hasAllowedValue/clo:valueName ?v }"):
            self.allowed[row["k"]].add(row["v"])
        self.value_source = collections.defaultdict(set)    # key iri -> {"inherit","team-default","ask"}
        for row in _q(st, "SELECT ?k ?s WHERE { ?k clo:valueSource ?s }"):
            self.value_source[row["k"]].add(row["s"])
        self.untaggable = {r["r"] for r in _q(st, "SELECT ?r WHERE { ?r clo:hasResourceType ?t . ?t a clo:UntaggableType }")}
        self.prefixes = [r["p"] for r in _q(st, "SELECT DISTINCT ?p WHERE { ?c clo:reservedPrefix ?p }")]
        managed = self.required | self.needed
        self.managed_names = {self.keyname[k] for k in managed if k in self.keyname} | set(self.canon.values())
        self.managed_norm = {norm(n): n for n in self.managed_names}
        self.syn_norm = {norm(self.keyname[m]): c for m, c in self.canon.items() if m in self.keyname}
        self.env_names = {n for n in self.managed_names if norm(n) in ("environment", "env")}
        # tag-derived ownership (e.g. a CMDB merge that reads the owner tag): the key, if declared
        self.ownership_key = {r["k"] for r in _q(st, "SELECT ?k WHERE { ?o clo:ownershipFromKey ?k }")}
        self.key_by_name = {}
        for k, n in self.keyname.items():
            self.key_by_name.setdefault(n, k)

    def is_system(self, name):
        low = name.lower()
        return any(low.startswith(p.lower()) for p in self.prefixes)

    def variant_of(self, k):
        """Canonical managed key name that key iri k spells differently, or None."""
        name = self.keyname.get(k)
        if name is None or self.is_system(name):
            return None
        if k in self.canon and self.canon[k] != name:
            return self.canon[k]
        c = self.syn_norm.get(norm(name))           # case/separator variant of a declared member
        if c is not None and c != name:
            return c
        n = self.managed_norm.get(norm(name))
        if n is not None and n != name:
            return n
        return None

    def roles(self, r, k):
        pols = [p for p in self.gov.get(r, ()) if k in self.pol_req.get(p, ())]
        out = set()
        for p in pols:
            rs = self.policy_roles.get((p, k))
            out |= rs if rs else {"policy: " + self.policy_label.get(p, loc(p))}
        return sorted(out)

    # ── repairs (I-18, I-21, I-22) ─────────────────────────────────────────────
    def team_values(self):
        """(team, key) -> values, and (account, key) -> values, over all labelled resources."""
        tv = collections.defaultdict(collections.Counter)
        for r, ls in self.labels.items():
            for t in self.owner.get(r, ()):
                for k, v in ls.items():
                    tv[(t, k)][v] += 1
            for a in self.account.get(r, ()):
                for k, v in ls.items():
                    tv[("acct", a, k)][v] += 1
        return tv

    @staticmethod
    def dominant(vals):
        if not vals:
            return None
        v, n = vals.most_common(1)[0]
        return v if n >= TEAM_DEFAULT_MIN and n / sum(vals.values()) >= TEAM_DEFAULT_SHARE else None

    def plan(self, r, k, tv):
        """Repair proposal for missing key k on r. Returns (action, value or None, rule)."""
        src = self.value_source.get(k, set())
        # inherit from a parent that carries the key (I-21)
        if self.repair_policy in ("naive", "majority") or "inherit" in src:
            v = self.inherit.get((r, k))                 # rules/cwa/I-21.rq
            if v is not None:
                return ("inherit", v, "I-21")
        if (self.repair_policy == "safe" and "account-default" in src) or (
                self.repair_policy == "majority" and self.keyname.get(k) in self.env_names):
            for a in sorted(self.account.get(r, ())):
                vals = tv.get(("acct", a, k))
                v = self.dominant(vals) if self.repair_policy == "safe" else (vals.most_common(1)[0][0] if vals else None)
                if v is not None:
                    return ("account-default", v, "I-18")
        teams = self.owner.get(r, set())
        if len(teams) == 1:
            t = next(iter(teams))
            vals = tv.get((t, k))
            if vals:
                v, n = vals.most_common(1)[0]
                tot = sum(vals.values())
                if self.repair_policy in ("naive", "majority"):
                    return ("team-default", v, "I-18")
                if "team-default" in src and n >= TEAM_DEFAULT_MIN and n / tot >= TEAM_DEFAULT_SHARE:
                    return ("team-default", v, "I-18")
            return ("ask-owner", None, None)
        if len(teams) > 1:
            return ("resolve-ownership", None, "I-27")
        return ("assign-owner", None, "I-26")

    # ── the audit ──────────────────────────────────────────────────────────────
    def run(self):
        st, raw = self.st, []
        add = lambda **f: raw.append(f)
        tv = self.team_values()
        self.inherit = {}
        self.propagation = sorted(rule(st, "I-21"), key=lambda x: (x["r"], x["k"], x["parent"]))
        for row in self.propagation:
            self.inherit.setdefault((row["r"], row["k"]), row["value"])
        unlabelled = {row["r"] for row in rule(st, "I-11")}
        for r in unlabelled:
            add(rule="I-11", r=r)
        missing = collections.defaultdict(list)
        for row in rule(st, "I-07"):
            missing[row["r"]].append(row["k"])
        for r, ks in missing.items():
            present = self.labels.get(r, {})
            for k in sorted(set(ks)):
                kname = self.keyname.get(k, loc(k))
                syn = next((k2 for k2 in present if self.variant_of(k2) == kname), None)
                if syn is not None:
                    add(rule="I-22", r=r, k=k, used=self.keyname.get(syn), repair=("rename", self.keyname.get(syn)),
                        roles=self.roles(r, k))
                else:
                    add(rule="I-07", r=r, k=k, roles=self.roles(r, k), repair=self.plan(r, k, tv))
        # redundant synonym: canonical key and a variant both present
        for r, ls in self.labels.items():
            names = {self.keyname.get(k) for k in ls}
            for k in ls:
                c = self.variant_of(k)
                if c and c in names:
                    add(rule="I-22r", r=r, k=self.key_by_name.get(c), used=self.keyname.get(k))
        for row in rule(st, "I-09"):
            k = row["k"]
            sugg = sorted((lev(row["value"], a), a) for a in self.allowed.get(k, ()))
            add(rule="I-09", r=row["r"], k=k, value=row["value"])
            if sugg and sugg[0][0] <= EDIT_DISTANCE:
                add(rule="I-20", r=row["r"], k=k, value=row["value"], suggestion=sugg[0][1])
        for rid in ("I-13", "I-14"):
            for row in rule(st, rid):
                if not self.is_system(self.keyname.get(row["k"], "")):
                    add(rule=rid, r=row["r"], k=row["k"], detail=row.get("what"))
        for row in rule(st, "I-15"):
            add(rule="I-15", r=row["r"], k=row["k"], detail=row["why"])
        for row in rule(st, "I-16"):
            add(rule="I-16", r=row["r"], detail=f'{row["ka"]}={row["va"]} & {row["kb"]}={row["vb"]}')
        for row in rule(st, "I-17"):
            name = row["name"]
            if self.is_system(name) or self.variant_of(row["k"]):
                continue
            close = sorted((lev(norm(name), m), self.managed_norm[m]) for m in self.managed_norm)
            if close and close[0][0] <= EDIT_DISTANCE and len(norm(name)) >= 4:
                add(rule="I-20", r=row["r"], k=row["k"], suggestion=close[0][1])
            else:
                add(rule="I-17", r=row["r"], k=row["k"])
        for row in rule(st, "I-26"):
            add(rule="I-26", r=row["r"])
        for row in rule(st, "I-27"):
            add(rule="I-27", r=row["r"], detail=row["teams"])
        for row in rule(st, "I-28"):
            add(rule="I-28", r=row["r"])
        # team conventions: declared synonyms (I-25) and variants of managed keys
        conv = set()
        for row in _q(st, "SELECT ?t ?k WHERE { ?t a clo:Team ; clo:usesKey ?k }"):
            c = self.variant_of(row["k"])
            if c:
                conv.add((row["t"], self.keyname[row["k"]], c))
        for t, used, c in sorted(conv):
            add(rule="I-25", r=None, team=t, used=used, canonical=c)
        # environment at risk (I-12)
        err_res = {f["r"] for f in raw if f.get("r") and SEVERITY.get(f["rule"]) == ERROR}
        env_names = self.env_names
        by_env = collections.defaultdict(set)
        for r, ls in self.labels.items():
            info = self.resources.get(r)
            if not info or info["scope"] != "true" or info["complete"] != "true":
                continue
            for k, v in ls.items():
                nm = self.keyname.get(k, "")
                if nm in env_names or self.variant_of(k) in env_names:
                    by_env[v].add(r)
        for v, rs in sorted(by_env.items()):
            bad = len(rs & err_res)
            if len(rs) >= 2 and bad / len(rs) >= ENV_AT_RISK:
                add(rule="I-12", r=None, value=v, n=len(rs), bad=bad)
        self.raw = raw
        return raw

    def coverage(self):
        """Per role: resources governed by a policy serving the role, and those carrying all its keys."""
        out = []
        roles = list(_q(self.st, "SELECT ?ro ?n WHERE { ?ro a clo:GovernanceRole ; rdfs:label ?n }"))
        for ro in roles:
            keys = {row["k"] for row in _q(self.st, f"SELECT ?k WHERE {{ <{ro['ro']}> clo:needsLabel ?k }}")}
            rs = {row["r"] for row in _q(self.st, f"""SELECT DISTINCT ?r WHERE {{ ?r a clo:AuditableResource ;
                  clo:recordComplete true ; clo:governedBy ?p . ?p clo:servesRole <{ro['ro']}> }}""")}
            cov = sum(1 for r in rs if keys <= set(self.labels.get(r, {})))
            out.append({"role": ro["n"], "governed": len(rs), "covered": cov, "keys": sorted(self.keyname.get(k, k) for k in keys)})
        return sorted(out, key=lambda x: x["role"])

    def cross_provider(self, key="environment"):
        rows = rule(self.st, "I-19", KEY=f'"{key}"')
        per_kind = collections.defaultdict(dict)
        for r in rows:
            n, c = int(r["n"]), int(r["covered"])
            per_kind[loc(r["kind"])][loc(r["provider"])] = (c, n)
        flagged = []
        for kind, provs in sorted(per_kind.items()):
            pct = {p: 100.0 * c / n for p, (c, n) in provs.items() if n}
            if len(pct) > 1 and max(pct.values()) - min(pct.values()) > COVERAGE_GAP:
                flagged.append({"kind": kind, "coverage": {p: f"{c}/{n}" for p, (c, n) in provs.items()}})
        return {"key": key, "per_kind": {k: {p: f"{c}/{n}" for p, (c, n) in v.items()} for k, v in per_kind.items()},
                "flagged": flagged}

    def root_causes(self, raw=None):
        """One finding per (resource, cause): an unlabelled resource is one finding listing its missing
        keys, not one per key; a missing key repaired by a rename is one I-22 finding."""
        raw = raw if raw is not None else self.raw
        unl = {f["r"] for f in raw if f["rule"] == "I-11"}
        no_owner = {f["r"] for f in raw if f["rule"] == "I-26"}
        out, folded = [], collections.defaultdict(list)
        for f in raw:
            if f["rule"] == "I-07" and f["r"] in unl:
                folded[f["r"]].append(self.keyname.get(f["k"], f["k"]))
                continue
            # tag-derived ownership: a missing owner key and "no owning team" are one cause (I-26);
            # on an unlabelled resource both are folded into I-11
            if self.ownership_key and f["rule"] == "I-07" and f["k"] in self.ownership_key and f["r"] in no_owner:
                continue
            if self.ownership_key and f["rule"] == "I-26" and f["r"] in unl:
                continue
            out.append(dict(f))
        for f in out:
            if f["rule"] == "I-11":
                f["missing"] = sorted(folded.get(f["r"], []))
        return out


def summarise(audit, findings):
    c = collections.Counter(f["rule"] for f in findings)
    return dict(sorted(c.items()))


def to_json(audit, raw, roots):
    """Serialisable report (also read by tools/clo_viz.py)."""
    def rid(r):
        return audit.resources.get(r, {}).get("id") or loc(r)

    def fmt(f):
        rep = f.get("repair")
        txt = None
        if rep:
            act, val = rep[0], rep[1]
            key = audit.keyname.get(f.get("k"), "")
            txt = {"rename": f"rename '{val}' to '{key}'", "inherit": f"set {key}={val} (inherited from parent)",
                   "team-default": f"set {key}={val} (owning team's default)",
                   "account-default": f"set {key}={val} (account's default)",
                   "ask-owner": f"ask the owning team for '{key}'",
                   "assign-owner": f"assign an owning team, then set '{key}'",
                   "resolve-ownership": f"resolve the ownership conflict, then set '{key}'"}[act]
        return {"rule": f["rule"], "severity": SEVERITY.get(f["rule"], INFO),
                "resource": rid(f["r"]) if f.get("r") else None, "iri": f.get("r"),
                "key": audit.keyname.get(f.get("k")) if f.get("k") else None,
                "roles": f.get("roles"), "repair": txt,
                "repair_value": rep[1] if rep and rep[0] in ("inherit", "team-default", "account-default") else None,
                "repair_action": rep[0] if rep else None,
                **{k: v for k, v in f.items() if k in ("used", "value", "suggestion", "detail", "missing",
                                                      "canonical", "n", "bad")},
                **({"team": audit.team_label.get(f["team"], loc(f["team"]))} if f.get("team") else {})}
    res = {loc(r): {"id": v.get("id"), "type": v.get("type"), "provider": loc(v.get("prov")),
                    "category": loc(v.get("cat")), "complete": v.get("complete") == "true",
                    "in_scope": v.get("scope") == "true",
                    "teams": sorted(audit.team_label.get(t, loc(t)) for t in audit.owner.get(r, ()))}
           for r, v in audit.resources.items()}
    prop = [[rid(p["r"]), audit.keyname.get(p["k"], loc(p["k"])), rid(p["parent"]), p["value"]]
            for p in getattr(audit, "propagation", [])]
    return {"resources": res, "findings": [fmt(f) for f in roots], "propagation": prop, "raw_counts": summarise(audit, raw),
            "root_cause_counts": summarise(audit, roots), "role_coverage": audit.coverage(),
            "no_verdict": sorted(v["id"] or loc(r) for r, v in audit.resources.items()
                                 if v["scope"] == "true" and v.get("complete") != "true"),
            "out_of_scope": sorted(v["id"] or loc(r) for r, v in audit.resources.items()
                                   if v["scope"] != "true" and r in audit.untaggable),
            "support_unknown": sorted(v["id"] or loc(r) for r, v in audit.resources.items()
                                      if v["scope"] != "true" and r not in audit.untaggable)}
