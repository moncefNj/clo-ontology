#!/usr/bin/env python3
"""
bench_reasoner.py -- measure the cost of one HermiT realisation of CLO over
whole A-Boxes (wall-clock time and peak memory).

What it measures, for each A-Box file given on the command line:
  * wall-clock time of the HermiT call (Owlready2 sync_reasoner_hermit,
    with property-value inference, as in the production pipeline);
  * peak resident memory of the Java reasoner process (ru_maxrss of children);
  * number of resources (individuals of clo:CloudResource) in the A-Box.

Each run happens in a fresh subprocess so that Owlready2's quadstore and the
JVM start cold every time. Results go to a CSV, one row per run.

Usage
-----
  pip install -r requirements.txt            # Java 8+ required
  python3 tools/gen_abox.py --n 800 --out a800.nt
  python3 tools/bench_reasoner.py --tbox ontology/clo_ontology_v8.ttl \
      --abox a800.nt --runs 3 --out bench.csv

Inputs may be Turtle, N-Triples or RDF/XML; Turtle is converted to N-Triples
with rdflib because Owlready2 does not parse Turtle.
"""
import argparse
import csv
import json
import os
import platform
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CLO_NS = "http://example.org/clo/ontology/clo#"


def to_ntriples(path: Path, workdir: Path) -> Path:
    """Owlready2 reads RDF/XML, OWL/XML and N-Triples, not Turtle."""
    if path.suffix.lower() not in (".ttl", ".turtle"):
        return path
    import rdflib
    g = rdflib.Graph()
    g.parse(str(path), format="turtle")
    out = workdir / (path.stem + ".nt")
    g.serialize(str(out), format="nt")
    return out


def single_run(tbox: str, abox: str, ns: str) -> dict:
    """Executed in a child process: load, reason, report."""
    import owlready2 as ow
    world = ow.World()
    world.get_ontology(Path(tbox).resolve().as_uri()).load()
    onto = world.get_ontology(Path(abox).resolve().as_uri()).load()
    cr = world.search_one(iri=ns + "CloudResource")
    n_res = len(list(cr.instances(world=world))) if cr is not None else -1

    t0 = time.perf_counter()
    with onto:
        ow.sync_reasoner_hermit(world, infer_property_values=True,
                                debug=0)
    wall = time.perf_counter() - t0

    # Java runs as a child of this process: its peak RSS is in RUSAGE_CHILDREN
    # (kilobytes on Linux, bytes on macOS).
    rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if platform.system() == "Darwin":
        rss //= 1024
    return {"resources": n_res, "wall_s": round(wall, 3),
            "peak_rss_mb": round(rss / 1024, 1)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tbox", required=True)
    ap.add_argument("--abox", required=True, nargs="+")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--ns", default=CLO_NS, help="CLO namespace IRI")
    ap.add_argument("--out", default="bench.csv")
    ap.add_argument("--_child", nargs=2, help=argparse.SUPPRESS)
    a = ap.parse_args()

    if a._child:                                   # inner process
        print(json.dumps(single_run(a._child[0], a._child[1], a.ns)))
        return

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        tbox = to_ntriples(Path(a.tbox), td)
        rows = []
        for abox_in in a.abox:
            abox = to_ntriples(Path(abox_in), td)
            for run in range(1, a.runs + 1):
                p = subprocess.run(
                    [sys.executable, __file__, "--tbox", a.tbox, "--abox", "x",
                     "--ns", a.ns, "--_child", str(tbox), str(abox)],
                    capture_output=True, text=True)
                if p.returncode != 0:
                    print(p.stderr, file=sys.stderr)
                    sys.exit(f"run failed on {abox_in}")
                r = json.loads(p.stdout.strip().splitlines()[-1])
                r.update(abox=Path(abox_in).name, run=run)
                rows.append(r)
                print(f"{r['abox']:<24} run {run}: {r['resources']} resources, "
                      f"{r['wall_s']} s, {r['peak_rss_mb']} MB")

    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["abox", "run", "resources",
                                          "wall_s", "peak_rss_mb"])
        w.writeheader()
        w.writerows(rows)
    print(f"\nwrote {a.out}  (host: {platform.processor() or platform.machine()},"
          f" {os.cpu_count()} cpus, Python {platform.python_version()})")


if __name__ == "__main__":
    main()
