"""
oracle.py -- an independent reference implementation of CLO's rule semantics.

It reads the generator's model (eval/gen_corpus.py, JSON) and computes the
expected root-cause findings with plain Python data structures: policy reach is
computed from the organisation tree, the team list, the type catalogue and the
composition links directly, without RDF, SPARQL or any reasoner. Agreement with
CLO (eval/eval_rules.py) is therefore a differential test of two
implementations of the same specification (rules/cwa/*.rq headers, clo/audit.py
docstrings, Table 3 of the paper).
"""
import collections
import re

RESERVED = {"AWS": ["aws:"], "Azure": ["microsoft", "azure", "windows"], "GCP": ["goog-", "google-"],
            "Kubernetes": ["kubernetes.io/", "k8s.io/"]}
CONSTRAINT = {"AWS": (False, 128, 256), "Azure": (False, 512, 256), "GCP": (True, 63, 63),
              "Kubernetes": (False, 63, 63), "GitHub": (True, 50, 50)}
ORCHESTRATORS = {"Kubernetes"}   # ContainerOrchestrationProvider in the T-Box
TEAM_DEFAULT_SHARE, TEAM_DEFAULT_MIN, ENV_AT_RISK, EDIT = 0.8, 2, 0.2, 2
ERROR_RULES = {"I-07", "I-09", "I-11", "I-13", "I-14", "I-15", "I-16", "I-22", "I-26", "I-27", "I-28"}


def norm(s):
    return re.sub(r"[-_ .:/]", "", s.lower())


def lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def system(name):
    low = name.lower()
    return any(low.startswith(p) for ps in RESERVED.values() for p in ps)


class Oracle:
    def __init__(self, m):
        self.m = m
        self.cat = m["catalogue"]
        self.res = {r["id"]: r for r in m["resources"]}
        self.ou_parent = {o["id"]: o["parent"] for o in m["ous"]}
        self.acct = {a["id"]: a for a in m["accounts"]}
        self.team = {t["id"]: t for t in m["teams"]}
        self.pol_keys = {}
        for p in m["policies"]:
            ks = set(p["requires"])
            for ro in p["serves"]:
                ks |= set(m["roles"][ro])
            self.pol_keys[p["id"]] = ks
        self.required_any = set().union(*self.pol_keys.values())
        self.needed = {k for ks in m["roles"].values() for k in ks}
        self.canon_of = {}
        for c, syns in m["synonyms"].items():
            for s in [c] + syns:
                self.canon_of[s] = c
        self.syn_norm = {norm(s): c for s, c in self.canon_of.items()}
        self.managed = self.required_any | self.needed | set(m["synonyms"])
        self.managed_norm = {norm(n): n for n in self.managed}
        self._gov = {}

    def provider(self, r):
        return r["provider"]

    def scope(self, r):
        return any(self.cat.get(t, {}).get("support") in ("full", "partial") for t in r["types"])

    def categories(self, r):
        return {self.cat.get(t, {}).get("category") for t in r["types"]} - {None}

    def ou_chain(self, ou):
        out = []
        while ou:
            out.append(ou)
            ou = self.ou_parent.get(ou)
        return out

    def governing(self, rid):
        if rid in self._gov:
            return self._gov[rid]
        r = self.res[rid]
        a = self.acct[r["account"]]
        pols = set()
        for p in self.m["policies"]:
            kind, tgt = p["attach"]
            if kind == "ou" and tgt in self.ou_chain(a["ou"]):
                pols.add(p["id"])
            elif kind == "account" and tgt == a["id"]:
                pols.add(p["id"])
            elif kind == "team" and tgt in r["owners"]:
                pols.add(p["id"])
            elif kind == "category" and tgt in self.categories(r):
                pols.add(p["id"])
        if r["parent"]:
            pols |= self.governing(r["parent"])
        self._gov[rid] = pols
        return pols

    def required(self, rid):
        return set().union(*[self.pol_keys[p] for p in self.governing(rid)]) if self.governing(rid) else set()

    def variant_of(self, name):
        if system(name):
            return None
        c = self.canon_of.get(name)
        if c is not None and c != name:
            return c
        c = self.syn_norm.get(norm(name))
        if c is not None and c != name:
            return c
        n = self.managed_norm.get(norm(name))
        if n is not None and n != name:
            return n
        return None

    def unmanaged(self, name):
        return (name not in self.required_any and name not in self.needed and name not in self.canon_of
                and name not in self.m["vocab"])

    def findings(self):
        F, raw_err = set(), set()
        for rid, r in self.res.items():
            tags = r["tags"]
            prov = self.provider(r)
            if self.scope(r) and r["complete"]:
                req = self.required(rid)
                if not tags:
                    F.add(("I-11", rid, tuple(sorted(req))))
                    raw_err.add(rid)
                else:
                    for k in sorted(req):
                        if k in tags:
                            continue
                        raw_err.add(rid)
                        if any(self.variant_of(k2) == k for k2 in tags):
                            F.add(("I-22", rid, k))
                        else:
                            F.add(("I-07", rid, k))
                if not r["owners"]:
                    F.add(("I-26", rid))
                    raw_err.add(rid)
            names = set(tags)
            for k, v in tags.items():
                c = self.variant_of(k)
                if c and c in names:
                    F.add(("I-22r", rid, c, k))
                if k in self.m["vocab"] and v not in self.m["vocab"][k]:
                    F.add(("I-09", rid, k, v))
                    raw_err.add(rid)
                    s = sorted((lev(v, a), a) for a in self.m["vocab"][k])
                    if s and s[0][0] <= EDIT:
                        F.add(("I-20", rid, k, s[0][1]))
                lo, kmax, vmax = CONSTRAINT.get(prov, (False, None, None))
                if not system(k):
                    if lo and k.lower() != k:
                        F.add(("I-13", rid, k)); raw_err.add(rid)
                    if kmax is not None and len(k) > kmax:
                        F.add(("I-14", rid, k, "key")); raw_err.add(rid)
                    if vmax is not None and len(v) > vmax:
                        F.add(("I-14", rid, k, "value")); raw_err.add(rid)
                for owner, ps in RESERVED.items():
                    if owner != prov and owner not in ORCHESTRATORS and any(k.lower().startswith(p) for p in ps):
                        F.add(("I-15", rid, k, "reserved by another provider")); raw_err.add(rid)
                if self.unmanaged(k) and not system(k) and not self.variant_of(k):
                    s = sorted((lev(norm(k), mn), self.managed_norm[mn]) for mn in self.managed_norm)
                    if s and s[0][0] <= EDIT and len(norm(k)) >= 4:
                        F.add(("I-20", rid, k, s[0][1]))
                    else:
                        F.add(("I-17", rid, k))
            for ka, va, kb, vb in self.m["conflicts"]:
                if tags.get(ka) == va and tags.get(kb) == vb:
                    F.add(("I-16", rid, f"{ka}={va} & {kb}={vb}")); raw_err.add(rid)
            if len(set(r["owners"])) > 1:
                F.add(("I-27", rid)); raw_err.add(rid)
            if len(set(r["types"])) > 1:
                F.add(("I-28", rid)); raw_err.add(rid)
        conv = set()
        for rid, r in self.res.items():
            for t in r["owners"]:
                for k in r["tags"]:
                    c = self.variant_of(k)
                    if c:
                        conv.add(("I-25", self.team[t]["name"], k, c))
        F |= conv
        env_names = {n for n in self.managed if norm(n) in ("environment", "env")}
        by_env = collections.defaultdict(set)
        for rid, r in self.res.items():
            if not (self.scope(r) and r["complete"]):
                continue
            for k, v in r["tags"].items():
                if k in env_names or self.variant_of(k) in env_names:
                    by_env[v].add(rid)
        for v, rs in by_env.items():
            bad = len(rs & raw_err)
            if len(rs) >= 2 and bad / len(rs) >= ENV_AT_RISK:
                F.add(("I-12", v, len(rs), bad))
        F |= self.propagation() | self.coverage()
        return F

    def ancestors(self, rid):
        out, p = [], self.res[rid]["parent"]
        while p:
            out.append(p)
            p = self.res[p]["parent"]
        return out

    def propagation(self):
        """I-21: a required key missing on a complete, in-scope record and carried by a (transitive)
        partOf ancestor; one tuple per (record, key, ancestor, ancestor's value)."""
        P = set()
        for rid, r in self.res.items():
            if not (self.scope(r) and r["complete"]):
                continue
            for k in self.required(rid):
                if k in r["tags"]:
                    continue
                for a in self.ancestors(rid):
                    if k in self.res[a]["tags"]:
                        P.add(("I-21", rid, k, a, self.res[a]["tags"][k]))
        return P

    def coverage(self, key="environment"):
        """I-19: per (BaseKind, provider), complete in-scope records and those carrying `key` verbatim."""
        n, c = collections.Counter(), collections.Counter()
        for rid, r in self.res.items():
            if not (self.scope(r) and r["complete"]):
                continue
            for bk in {self.cat.get(t, {}).get("basekind") for t in r["types"]} - {None}:
                n[(bk, r["provider"])] += 1
                c[(bk, r["provider"])] += key in r["tags"]
        return {("I-19", bk, pv, f"{c[(bk, pv)]}/{n[(bk, pv)]}") for bk, pv in n}


def clo_tuples(rep):
    """The same tuples from CLO's findings.json (root causes)."""
    T = set()
    for f in rep["findings"]:
        r, k = f.get("resource"), f.get("key")
        rule = f["rule"]
        if rule == "I-11":
            T.add((rule, r, tuple(sorted(f.get("missing") or []))))
        elif rule in ("I-07", "I-22", "I-13", "I-17"):
            T.add((rule, r, k if rule != "I-17" else k))
        elif rule == "I-22r":
            T.add((rule, r, k, f.get("used")))
        elif rule == "I-09":
            T.add((rule, r, k, f.get("value")))
        elif rule == "I-20":
            T.add((rule, r, k, f.get("suggestion")))
        elif rule == "I-14":
            T.add((rule, r, k, f.get("detail")))
        elif rule == "I-15":
            T.add((rule, r, k, f.get("detail")))
        elif rule == "I-16":
            T.add((rule, r, f.get("detail")))
        elif rule in ("I-26", "I-27", "I-28"):
            T.add((rule, r))
        elif rule == "I-25":
            T.add((rule, f.get("team"), f.get("used"), f.get("canonical")))
        elif rule == "I-12":
            T.add((rule, f.get("value"), f.get("n"), f.get("bad")))
    for r, k, parent, value in rep.get("propagation", []):
        T.add(("I-21", r, k, parent, value))
    for bk, provs in (rep.get("cross_provider") or {}).get("per_kind", {}).items():
        for pv, cn in provs.items():
            T.add(("I-19", bk, pv, cn))
    return T
