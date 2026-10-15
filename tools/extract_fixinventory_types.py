#!/usr/bin/env python3
"""
extract_fixinventory_types.py -- build the CLO resource-type catalogue
(clo_types.ttl) from the source code of Fix Inventory.

CLO's 40 BaseKinds correspond one-to-one to the base resource classes of Fix
Inventory's unified data model (fixlib/baseresources.py: BaseInstance ->
"instance" -> clo:InstanceKind). Every concrete Fix Inventory resource class
declares its kind string (e.g. "aws_ec2_instance") and inherits from one of
those base classes, so the type -> BaseKind mapping can be read off the class
hierarchy without running the collectors.

The script parses the plugin sources with Python's ast module (nothing is
imported or executed) and, for every class that inherits from BaseResource:

  * kind            the `kind: ClassVar[str] = "..."` value;
  * BaseKind        the most specific fixlib base class that has a CLO
                    counterpart (via the "UDM: <kind>" comment of each BaseKind);
  * provider        from the plugin (aws -> clo:AWS, k8s -> clo:Kubernetes, ...);
  * labelingSupport "none" for phantom resources (Fix Inventory: "does not
                    maintain tags"); otherwise taken from the curated file
                    labeling_support_curated.csv (one row per kind, with the
                    provider documentation URL used as evidence). "unknown"
                    rows are NOT asserted: under OWA such a type is neither
                    in nor out of audit scope until someone curates it.

                    Tag support is deliberately not inferred from the
                    collector code: Fix Inventory maps a `tags` attribute on
                    many kinds that do not support tags (e.g. IAM groups, GCP
                    firewalls), so a source-code heuristic over-approximates.

Classes with no CLO BaseKind are counted and listed but not emitted, because
CLO requires every ResourceType to implement exactly one BaseKind.

Usage:
  git clone https://github.com/someengineering/fixinventory
  python3 tools/extract_fixinventory_types.py --fix fixinventory \
      --clo ontology/clo_ontology_v8.ttl --curation data/labeling_support_curated.csv \
      --out ontology/clo_types.ttl --report data/types_report.json
"""
import argparse
import ast
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

CLO = "http://example.org/clo/ontology/clo#"
PLUGIN_PROVIDER = {
    "aws": "AWS", "azure": "Azure", "gcp": "GCP", "k8s": "Kubernetes",
    "digitalocean": "DigitalOcean", "github": "GitHub", "dockerhub": "DockerHub",
    "slack": "Slack", "onelogin": "OneLogin",
}


def kind_of(cls):
    for st in cls.body:
        if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) \
                and st.target.id == "kind" and isinstance(st.value, ast.Constant):
            return st.value.value
    return None


def base_names(cls):
    out = []
    for b in cls.bases:
        if isinstance(b, ast.Name):
            out.append(b.id)
        elif isinstance(b, ast.Attribute):
            out.append(b.attr)
    return out


def load_classes(root, scope):
    classes = {}
    for path in sorted(root.rglob("*.py")):
        if "/test" in str(path):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                classes.setdefault((scope, node.name), {
                    "bases": base_names(node), "kind": kind_of(node),
                    "file": str(path.relative_to(root.parent.parent)),
                })
    return classes


def clo_basekinds(clo_ttl):
    import rdflib
    g = rdflib.Graph(); g.parse(clo_ttl)
    out = {}
    for k in g.subjects(rdflib.RDFS.subClassOf, rdflib.URIRef(CLO + "BaseKind")):
        for c in g.objects(k, rdflib.RDFS.comment):
            m = re.match(r"UDM:\s*([a-z_]+)", str(c))
            if m:
                out[m.group(1)] = str(k).split("#")[1]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fix", required=True, help="Fix Inventory checkout")
    ap.add_argument("--clo", required=True)
    ap.add_argument("--curation", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", required=True)
    a = ap.parse_args()
    fix = Path(a.fix)
    commit = subprocess.run(["git", "-C", str(fix), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip() or "unknown"

    fixlib = load_classes(fix / "fixlib" / "fixlib", "fixlib")
    base_kind = {name: c["kind"] for (_, name), c in fixlib.items()}
    udm = clo_basekinds(a.clo)                      # "instance" -> "InstanceKind"

    def fixlib_ancestors(name, dist=0, out=None):
        """[(fixlib class, inheritance distance from `name`)]."""
        out = out if out is not None else {}
        c = fixlib.get(("fixlib", name))
        if c is None or out.get(name, 1 << 30) <= dist:
            return out
        out[name] = dist
        for b in c["bases"]:
            fixlib_ancestors(b, dist + 1, out)
        return out

    rows, unmapped, ambiguous, unmapped_kinds = [], Counter(), [], []
    for plugin, provider in PLUGIN_PROVIDER.items():
        pdir = fix / "plugins" / plugin
        cls = load_classes(pdir, plugin)

        def walk(name, depth=0, seen=None):
            """Yield (fixlib base name, depth) and plugin ancestors."""
            seen = seen if seen is not None else set()
            if name in seen:
                return [], []
            seen.add(name)
            c = cls.get((plugin, name))
            if c is None:
                return ([(n, depth + d) for n, d in fixlib_ancestors(name).items()]
                        if ("fixlib", name) in fixlib else []), []
            fl, pl = [], [name]
            for b in c["bases"]:
                f2, p2 = walk(b, depth + 1, seen)
                fl += f2; pl += p2
            return fl, pl

        for (_, name), c in cls.items():
            if not c["kind"]:
                continue
            fl, pl = walk(name)
            fl_names = [n for n, _ in fl]
            if "BaseResource" not in fl_names:
                continue                                   # attribute class
            phantom = "PhantomBaseResource" in fl_names
            # most specific fixlib base with a CLO counterpart (smallest depth)
            cands = sorted({(d, n) for n, d in fl if base_kind.get(n) in udm})
            kinds = {udm[base_kind[n]] for d, n in cands if d == cands[0][0]} if cands else set()
            if not kinds:
                unmapped[provider] += 1
                unmapped_kinds.append({"kind": c["kind"], "provider": provider,
                                       "fixlib_bases": sorted({n for n, _ in fl})})
                continue
            if len(kinds) > 1:
                ambiguous.append((c["kind"], sorted(kinds)))
            bk = sorted(kinds)[0]
            rows.append({"kind": c["kind"], "provider": provider, "basekind": bk,
                         "labelingSupport": "none" if phantom else None,
                         "phantom": phantom, "class": name, "file": c["file"]})

    import csv
    curated = {r["kind"]: r for r in csv.DictReader(open(a.curation))}
    for r in rows:
        if r["labelingSupport"] is None:
            cur = curated.get(r["kind"])
            r["labelingSupport"] = cur["support"] if cur else "unknown"
            r["evidence"] = cur["evidence_url"] if cur else ""
        else:
            r["evidence"] = "fixlib PhantomBaseResource: does not maintain tags"

    # de-duplicate kinds (a kind string may be declared twice)
    seen, uniq = set(), []
    for r in sorted(rows, key=lambda r: (r["provider"], r["kind"])):
        if r["kind"] not in seen:
            seen.add(r["kind"]); uniq.append(r)

    with open(a.out, "w") as f:
        f.write(f"""@prefix clo: <{CLO}> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix dc: <http://purl.org/dc/elements/1.1/> .
@prefix dcterms: <http://purl.org/dc/terms/> .

# GENERATED by extract_fixinventory_types.py -- do not edit by hand.
# Source: Fix Inventory (Apache-2.0), github.com/someengineering/fixinventory,
# commit {commit}. labelingSupport from labeling_support_curated.csv (sourced
# per kind from provider documentation); omitted where curation says unknown.

<http://example.org/clo/ontology/clo-types> a owl:Ontology ;
    dc:description "CLO resource-type catalogue: {len(uniq)} Fix Inventory kinds mapped to CLO BaseKinds." ;
    dc:source "https://github.com/someengineering/fixinventory/tree/{commit}" ;
    dcterms:license <https://www.apache.org/licenses/LICENSE-2.0> ;
    owl:versionInfo "8.0" .
dc:description a owl:AnnotationProperty .
dc:source a owl:AnnotationProperty .
dcterms:license a owl:AnnotationProperty .

""")
        for r in uniq:
            iri = "rt_" + re.sub(r"[^A-Za-z0-9_]", "_", r["kind"])
            support = (f' ;\n    clo:labelingSupport "{r["labelingSupport"]}"'
                       if r["labelingSupport"] in ("full", "none") else "")
            note = "" if support else "  # labelingSupport not curated (unknown)"
            f.write(f"""clo:{iri} a clo:ResourceType , owl:NamedIndividual ;
    clo:resourceTypeName "{r['kind']}" ;
    clo:implementsBaseKind clo:{r['basekind']} ;
    clo:hostedBy clo:{r['provider']}{support} .{note}

""")
    report = {
        "fixinventory_commit": commit,
        "types": len(uniq),
        "by_provider": Counter(r["provider"] for r in uniq),
        "by_support": Counter(r["labelingSupport"] for r in uniq),
        "by_provider_support": {p: Counter(r["labelingSupport"] for r in uniq if r["provider"] == p)
                                for p in sorted({r["provider"] for r in uniq})},
        "by_basekind": Counter(r["basekind"] for r in uniq),
        "basekinds_used": len({r["basekind"] for r in uniq}),
        "phantom": sum(r["phantom"] for r in uniq),
        "unmapped_resource_classes": unmapped,
        "unmapped_kinds": sorted(unmapped_kinds, key=lambda r: (r["provider"], r["kind"])),
        "ambiguous": ambiguous,
        "rows": uniq,
    }
    Path(a.report).write_text(json.dumps(report, indent=1, default=dict))
    print(f"{len(uniq)} types -> {a.out}; unmapped resource classes: {dict(unmapped)}; "
          f"ambiguous: {len(ambiguous)}")


if __name__ == "__main__":
    main()
