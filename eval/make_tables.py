#!/usr/bin/env python3
"""
make_tables.py -- every number of the paper's evaluation, generated from results/*.json.

Writes <out>/numbers.tex (\\newcommand macros) and <out>/tab_*.tex (table bodies), so
that the paper cannot drift from the measurements.

  python3 eval/make_tables.py --results results --out ../paper
"""
import argparse
import collections
import json
import os
import statistics

R = {}


def load(d, name):
    p = os.path.join(d, name)
    return json.load(open(p)) if os.path.exists(p) else None


def fmt(x, nd=0):
    if isinstance(x, float) and nd:
        return f"{x:.{nd}f}"
    return f"{int(round(x)):,}".replace(",", "{,}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    N = {}
    rq1 = load(a.results, "rq1_rules.json")
    rq2 = load(a.results, "rq2_real.json")
    rq3 = load(a.results, "rq3_baselines.json")
    rq4 = load(a.results, "rq4_engines_dl.json")
    rq4s = load(a.results, "rq4_engines_scale.json")
    rq4c = load(a.results, "rq4_conflicts.json")
    rep = load(a.results, "rq5_repairs.json")
    loop = load(a.results, "rq5_loop.json")
    e2e = load(a.results, "rq1_hermit.json")

    # ── RQ1 ──
    s = rq1["summary"]
    N["rqOneEstates"] = len(rq1["runs"])
    N["rqOneN"] = fmt(rq1["runs"][0]["n"])
    N["rqOneResources"] = fmt(sum(r["resources"] for r in rq1["runs"]))
    N["rqOneLabels"] = fmt(sum(r["labels"] for r in rq1["runs"]))
    N["rqOneFindings"] = fmt(sum(v["expected"] for v in s.values()))
    N["rqOneRules"] = len(s)
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import gen_corpus
    ms = [gen_corpus.build(r["n"], r["seed"]) for r in rq1["runs"]]
    N["rqOneComposition"] = fmt(100 * sum(1 for m in ms for x in m["resources"] if x["parent"])
                                / sum(len(m["resources"]) for m in ms))
    N["rqOneAccounts"] = fmt(len(ms[0]["accounts"])); N["rqOneTeams"] = fmt(len(ms[0]["teams"]))
    N["rqOneTypes"] = fmt(len(ms[0]["catalogue"]))
    N["rqOneAllExact"] = "yes" if all(v["fp"] == 0 and v["fn"] == 0 for v in s.values()) else "NO"
    P = collections.Counter(); D = collections.Counter(); DT = collections.Counter(); MISS = collections.Counter()
    for r in rq1["runs"]:
        for k, v in r["planted"].items():
            P[k] += v["planted"]; D[k] += v["detected"]; DT[k] += v.get("detected_team_level", 0)
            MISS.update(v.get("missed", {}))
    inc = sum(r["withheld"]["incomplete"] for r in rq1["runs"])
    N["rqOnePlanted"] = fmt(sum(P.values()) + inc)            # all planted defects, truncations included
    N["rqOnePlantedNI"] = fmt(sum(P.values()))                # defects other than truncated listings
    N["rqOnePlantedKinds"] = len(P) + 1
    N["rqOneDetected"] = fmt(sum(D.values()))
    N["rqOneDetectedTeam"] = fmt(sum(DT.values()))
    N["rqOneDetectedPct"] = fmt(100 * (sum(D.values()) + sum(DT.values())) / sum(P.values()))
    N["rqOneMissed"] = fmt(sum(MISS.values()))
    pick = lambda w: fmt(sum(v for k, v in MISS.items() if w in k))
    N["rqOneMissIncomplete"] = pick("incomplete"); N["rqOneMissScope"] = pick("scope")
    N["rqOneMissNotRequired"] = pick("not required"); N["rqOneMissSpelling"] = pick("spelling")
    N["rqOneMissOverwritten"] = pick("overwritten"); N["rqOneMissUnexplained"] = pick("unexplained")
    N["rqOneMissVariantManaged"] = pick("variant of a managed")
    N["rqOneIncomplete"] = fmt(sum(r["withheld"]["incomplete"] for r in rq1["runs"]))
    N["rqOneAbsenceOnIncomplete"] = fmt(sum(r["withheld"]["absence_findings_on_incomplete"] for r in rq1["runs"]))
    rules = sorted(s, key=lambda x: (int(x[2:4]), x))
    half = (len(rules) + 1) // 2
    rows = []
    for j, chunk in enumerate((rules[:half], rules[half:])):
        chunk = chunk + [""] * (half - len(chunk))
        rows.append(" & ".join([r"\textbf{Rule}"] + chunk) + r" \\")
        rows.append(" & ".join(["Expected"] + [fmt(s[c]["expected"]) if c else "" for c in chunk]) + r" \\")
        if j == 0:
            rows.append(r"\midrule")
    open(os.path.join(a.out, "tab_rq1.tex"), "w").write("\n".join(rows) + "\n")
    N["rqOneCols"] = half
    e2ec = load(a.results, "rq1_hermit_with_conflicts.json")
    if e2ec:
        N["rqOneDLconflictStatus"] = ",".join(sorted({r["timing"].get("status", "?") for r in e2ec["runs"]}))
    if e2e:
        N["rqOneDLn"] = fmt(e2e["runs"][0]["n"])
        N["rqOneDLruns"] = len(e2e["runs"])
        N["rqOneDLexact"] = "yes" if all(v["fp"] == 0 and v["fn"] == 0 for v in e2e["summary"].values()) else "NO"

    # ── RQ2 ──
    if rq2:
        i, n0 = rq2["ingest"], rq2["ingest_noext"]
        N["rqTwoRes"] = fmt(i["resources"])
        for p in ("AWS", "Azure", "GCP"):
            N["rqTwoRes" + p] = fmt(i["by_provider"][p])
        N["rqTwoKinds"] = fmt(i["kinds"])
        N["rqTwoAccounts"] = fmt(i["accounts"])
        N["rqTwoLabels"] = fmt(i["labels"])
        N["rqTwoKeys"] = fmt(i["distinct_keys"])
        N["rqTwoTagged"] = fmt(i["tagged"])
        N["rqTwoComplete"] = fmt(i["complete"])
        N["rqTwoCompletePct"] = fmt(100 * i["complete"] / i["resources"])
        N["rqTwoConflicts"] = fmt(i["conflicting_observations"])
        for k, v in i["completeness_rule"].items():
            N["rqTwoRule" + k] = fmt(v)
        tot0 = n0["resources"] + n0["unmapped_resources"]
        tot1 = i["resources"] + i["unmapped_resources"]
        N["rqTwoMappedNoExt"] = fmt(n0["resources"]); N["rqTwoMappedNoExtPct"] = fmt(100 * n0["resources"] / tot0)
        N["rqTwoMappedExtPct"] = fmt(100 * i["resources"] / tot1)
        N["rqTwoDistinctRecords"] = fmt(tot1)
        sub = sum(v for k, v in i["unmapped_resources_by_type"].items()
                  if k.startswith("azure ") and k.count("/") >= 2)
        N["rqTwoUnmappedSub"] = fmt(sub)
        N["rqTwoUnmappedRulesConf"] = fmt(sum(v for k, v in i["unmapped_resources_by_type"].items()
                                              if k.startswith("azure ") and (k.endswith("securityrules")
                                                                             or k.endswith("/configurations"))))
        N["rqTwoUnmapped"] = fmt(i["unmapped_resources"])
        N["rqTwoUnmappedTypes"] = fmt(i["unmapped_types"])
        N["rqTwoInScope"] = fmt(rq2["in_scope"])
        N["rqTwoNoVerdict"] = fmt(rq2["no_verdict"])
        N["rqTwoOutScope"] = fmt(rq2["out_of_scope"])
        N["rqTwoTeams"] = fmt(rq2["teams_from_owner_tags"])
        rc, raw = rq2["root_cause_counts"], rq2["raw_counts"]
        for k in ("I-07", "I-11", "I-22", "I-25", "I-26", "I-17", "I-20", "I-15", "I-12", "I-09"):
            N["rqTwoRC" + k.replace("-", "")] = fmt(rc.get(k, 0))
        N["rqTwoRawSeven"] = fmt(raw.get("I-07", 0))
        sp = rq2["spellings"]
        N["rqTwoEnvSpellings"] = ", ".join(rf"\code{{{k}}}~({v})" for k, v in sp.get("environment", {}).items())
        N["rqTwoOwnerSpellings"] = ", ".join(rf"\code{{{k}}}~({v})" for k, v in sp.get("owner", {}).items())
        N["rqTwoAppSpellings"] = ", ".join(rf"\code{{{k}}}~({v})" for k, v in sp.get("app", {}).items())
        N["rqTwoSuggestions"] = ", ".join(rf"\code{{{k}}}$\to$\code{{{v}}}" for k, v in rq2["suggestions_I20"])
        ex = rq2["export_checks"]
        N["rqTwoExportPairs"] = fmt(ex["pairs_on_no_verdict_records"])
        N["rqTwoExportRecords"] = fmt(ex["no_verdict_records"])
        N["rqTwoExportBuckets"] = fmt(ex["no_verdict_by_kind"].get("aws_s3_bucket", 0))
        N["rqTwoRenames"] = fmt(ex["renames_clo_reports_as_missing_elsewhere"])
        N["rqTwoISevenKeys"] = fmt(rq2.get("i17_distinct_keys", 0))
        ct = rq2.get("coverage_top_level")
        if ct:
            N["rqTwoCovTopPct"] = fmt(ct["pct"]); N["rqTwoAzureChild"] = fmt(ct["azure_child"])
        top = dict(rq2.get("i17_top_keys") or [])
        N["rqTwoMaidStatus"] = fmt(top.get("maid_status", 0)); N["rqTwoTestRunId"] = fmt(top.get("TestRunId", 0))
        N["rqTwoNameKey"] = fmt(top.get("Name", 0))
        N["rqTwoAuditS"] = fmt(rq2["timing"]["materialise_s"] + rq2["timing"]["audit_s"], 1)
        if "engines" in rq2:
            e = rq2["engines"]
            N["rqTwoE"] = fmt(e["clo-r"])
            for k in ("hermit", "pellet"):
                if isinstance(e.get(k), dict):
                    N["rqTwo" + k.capitalize() + "Eq"] = "identical" if e[k].get("equal") else (
                        f"different ({e[k].get('missing')} missing, {e[k].get('extra')} extra)" if e[k].get("equal") is False
                        else e[k].get("status"))
                    N["rqTwo" + k.capitalize() + "S"] = fmt(e[k]["wall_s"])

    val = load(a.results, "rq2_completeness.json")
    if val:
        t = val["complete_rules_total"]
        N["valSibling"] = fmt(t["with_sibling"]); N["valContra"] = fmt(t["contradicted"])
        N["valContraPct"] = f"{100 * val['complete_rules_contradiction_upper_bound']:.1f}"
        N["valContraBefore"] = fmt(t["contradicted_witness_before"])
        N["valContraBeforePct"] = f"{100 * val['complete_rules_contradiction_witness_before']:.1f}"
        n = val["per_rule"].get("N", {})
        N["valNSibling"] = fmt(n.get("with_sibling", 0)); N["valNShows"] = fmt(n.get("sibling_shows_tags", 0))
        L = []
        for rule in ("A1", "A2", "A3", "Z1", "G1"):
            x = val["per_rule"].get(rule, {})
            N["val" + rule + "Sib"] = fmt(x.get("with_sibling", 0)); N["val" + rule + "Con"] = fmt(x.get("contradicted", 0))

    # ── RQ3 ──
    if rq3:
        ag = rq3["aggregate"]
        names = {"CLO": r"\clo{}", "NATIVE": "AWS Config + Azure Policy", "NATIVE+": "\\quad + GCP custom constraints",
                 "CUSTODIAN": "Cloud Custodian", "OPA-idiom": "OPA, idiomatic", "OPA-team": "\\quad + team scope",
                 "OPA-full": "OPA, \\clo{} semantics", "CLO-noLC": r"\clo{} without local closure"}
        reads = {"A": "provider-side tags", "B": "inventory export"}
        L = []
        for setting in ("A", "B"):
            keys = [k for k in ag if k.startswith(setting + ":")]
            order = ["CLO", "OPA-full", "OPA-idiom", "OPA-team", "CUSTODIAN", "NATIVE", "NATIVE+", "CLO-noLC"]
            keys = [k for k in keys if k[2:] in order]
            keys.sort(key=lambda k: order.index(k[2:]))
            for j, k in enumerate(keys):
                v = ag[k]
                first = (rf"\multirow{{{len(keys)}}}{{*}}{{\parbox{{1.35cm}}{{{setting}: {reads[setting]}}}}}" if j == 0 else "")
                rf_ = f"{v['recall_flat']:.3f}" if v.get("recall_flat") is not None else "--"
                L.append(f"{first} & {names[k[2:]]} & {fmt(v['reported'])} & {v['precision']:.3f} & {v['recall']:.3f} & "
                         f"{rf_} & {fmt(v['fp'])} & {fmt(v['fn'])} \\\\")
            L.append(r"\midrule" if setting == "A" else "")
        open(os.path.join(a.out, "tab_rq3.tex"), "w").write("\n".join(L) + "\n")
        T = sum(r["_truth"] for r in rq3["runs"])
        N["rqThreeTruth"] = fmt(T)
        N["rqThreeTruthFlat"] = fmt(sum(r.get("_truth_flat", 0) for r in rq3["runs"]))
        for k, v in ag.items():
            if v.get("recall_flat") is not None:
                N["rqThree" + k.replace(":", "").replace("-", "").replace("+", "plus") + "RF"] = f"{v['recall_flat']:.3f}"
        N["rqThreeTruthIncomplete"] = fmt(sum(r["_truth_on_incomplete"] for r in rq3["runs"]))
        N["rqThreeSeeds"] = len(rq3["runs"])
        for k, v in ag.items():
            tag = k.replace(":", "").replace("-", "")
            tag = tag.replace("+", "plus")
            N["rqThree" + tag + "P"] = f"{v['precision']:.3f}"
            N["rqThree" + tag + "R"] = f"{v['recall']:.3f}"
            N["rqThree" + tag + "FP"] = fmt(v["fp"])
        N["rqThreeOPAidentical"] = "yes" if all(r["B:OPA-full"].get("identical_to_CLO") for r in rq3["runs"]) else "NO"
        ef = rq3["effort"]
        cols = ["CLO", "OPA-full", "OPA-idiom", "CUSTODIAN", "NATIVE"]
        L = [" & ".join(["Artefact size (lines)"] + [fmt(ef["size_lines"][c]) for c in cols]) + r" \\", r"\midrule"]
        short = {"S1": "S1 new role in the shared standard", "S2": "S2 a role needs one more key",
                 "S3": "S3 accept a new synonym", "S4": "S4 new type in a governed category", "S5": "S5 team-level policy"}
        for sc, v in ef["scenarios"].items():
            L.append(" & ".join([short.get(sc[:2], sc)] + ["--" if v[c] is None else fmt(v[c]) for c in cols]) + r" \\")
        open(os.path.join(a.out, "tab_effort.tex"), "w").write("\n".join(L) + "\n")
        tagc = {"CLO": "Clo", "OPA-full": "OpaFull", "OPA-idiom": "OpaTeam", "CUSTODIAN": "Cust", "NATIVE": "Native"}
        for c in cols:
            N["eff" + tagc[c] + "Size"] = fmt(ef["size_lines"][c])
            for sc, v in ef["scenarios"].items():
                N["eff" + tagc[c] + sc[:2]] = "--" if v[c] is None else fmt(v[c])
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        N["rqThreeRegoLines"] = fmt(sum(1 for l in open(os.path.join(here, "baselines", "rego", "full.rego"))
                                        if l.strip() and not l.lstrip().startswith("#")))
        def cause(sysname, word):
            fc = ag[sysname].get("fn_causes", {})
            return fmt(sum(v for k, v in fc.items() if word in k))
        for sysname, tag in (("A:NATIVE", "Native"), ("A:CUSTODIAN", "Cust"), ("A:OPA-idiom", "Opa"), ("A:OPA-team", "OpaTeam"),
                             ("A:NATIVE+", "NativePlus")):
            if sysname not in ag:
                continue
            N["rqThreeFN" + tag + "Provider"] = cause(sysname, "not covered")
            N["rqThreeFN" + tag + "Team"] = cause(sysname, "team policy")
            N["rqThreeFN" + tag + "Inherit"] = cause(sysname, "inherited")
            N["rqThreeFN" + tag + "Case"] = cause(sysname, "case variant")
            N["rqThreeFN" + tag + "Two"] = cause(sysname, "two-type")
        cv = rq3["custodian_validate"]
        N["rqThreeCustodianPolicies"] = fmt(sum(v["policies"] for v in cv.values()))
        N["rqThreeCustodianValid"] = "yes" if all(v["valid"] for v in cv.values()) else "NO"

    # ── RQ4 ──
    e2e_rows = {r["n"]: r for r in (load(a.results, "rq4_e2e.json") or {"rows": []})["rows"]}
    cyc = lambda n: (f"{e2e_rows[n]['wall_s']:.1f}" if e2e_rows[n]["wall_s"] < 100 else fmt(e2e_rows[n]["wall_s"])) if n in e2e_rows else "--"
    if rq4:
        L = []
        KEEP = {250, 1000, 2000, 16000, 64000}      # rows shown in the paper (all rows are in the JSON)
        for row in rq4["rows"]:
            if row["n"] not in KEEP:
                continue
            c = row["clo-r"]
            cells = [fmt(row["n"]), fmt(row["labels"]), fmt(c["E"]), f"{statistics.median(c['wall_s']):.2f}"]
            for e in ("owlrl", "hermit", "pellet"):
                x = row.get(e)
                if not x:
                    cells.append("--")
                elif x.get("status") == "timeout":
                    cells.append(r"$>$" + fmt(x.get("wall_s") // 100 * 100))
                else:
                    mark = r"$=$" if x.get("equal_to_clo_r") else rf"$-${fmt(x.get('missing_vs_clo_r', 0))}"
                    cells.append(f"{fmt(x['wall_s'])} ({mark})")
            cells.append(cyc(row["n"]))
            L.append(" & ".join(cells) + r" \\")
        if rq4s:
            for row in rq4s["rows"]:
                if row["n"] <= max(r["n"] for r in rq4["rows"]) or row["n"] not in KEEP:
                    continue
                c = row["clo-r"]
                L.append(" & ".join([fmt(row["n"]), fmt(row["labels"]), fmt(c["E"]),
                                     f"{statistics.median(c['wall_s']):.2f}", "--", "--", "--", cyc(row["n"])]) + r" \\")
        open(os.path.join(a.out, "tab_rq4.tex"), "w").write("\n".join(L) + "\n")
        rows = rq4["rows"]
        last = max((r for r in rows if r.get("hermit", {}).get("equal_to_clo_r")), key=lambda r: r["n"], default=None)
        if last:
            N["rqFourMaxEqN"] = fmt(last["n"])
            N["rqFourSpeedup"] = fmt(last["hermit"]["wall_s"] / statistics.median(last["clo-r"]["wall_s"]))
        N["rqFourAllEq"] = "yes" if all(r[e].get("equal_to_clo_r") for r in rows for e in ("hermit", "pellet")
                                        if e in r and r[e].get("status") == "ok") else "NO"
        ow = [r["owlrl"] for r in rows if "owlrl" in r and r["owlrl"].get("status") == "ok"]
        N["rqFourOwlrlMissing"] = fmt(ow[0]["missing_vs_clo_r"]) if ow else "--"
        cf = (rq4c or {}).get("conflicts")
        if cf:
            same, diff = cf["two types, same category"], cf["two types, different categories"]
            N["rqFourConfExtra"] = fmt(same.get("extra", 0))
            N["rqFourConfExtraRes"] = fmt(same.get("extra_resources", 0))
            N["rqFourConfDiff"] = diff.get("hermit_status", "?")
        if rq4s:
            big = max(rq4s["rows"], key=lambda r: r["n"])
            N["rqFourBigN"] = fmt(big["n"]); N["rqFourBigS"] = f"{statistics.median(big['clo-r']['wall_s']):.1f}"
            N["rqFourBigLabels"] = fmt(big["labels"])

    e2e4 = load(a.results, "rq4_e2e.json")
    if e2e4:
        rows = e2e4["rows"]
        for r in rows:
            N[f"eTwoE{r['n'] // 1000}k"] = f"{r['wall_s']:.0f}" if r["wall_s"] >= 10 else f"{r['wall_s']:.1f}"
            N[f"eTwoEAudit{r['n'] // 1000}k"] = f"{r['audit_s']:.0f}"
        big = rows[-1]
        N["eTwoEBigN"] = fmt(big["n"]); N["eTwoEBigS"] = f"{big['wall_s']:.0f}"
        N["eTwoEBigAuditShare"] = fmt(100 * big["audit_s"] / big["wall_s"])
        r2 = next((r for r in rows if r["n"] == 2000), rows[0])
        N["eTwoETwoS"] = f"{r2['wall_s']:.1f}"
        N["eTwoEPerK"] = f"{1000 * big['wall_s'] / big['n']:.2f}"

    sens = load(a.results, "rq5_sensitivity.json")
    if sens:
        L = []
        for row in sens["rows"]:
            cells = [f"{100 * row['violate']:.0f}\\,\\%"]
            for pol in ("safe", "majority", "naive"):
                x = row[pol]
                cells += [fmt(100 * x["coverage"]), f"{100 * x['accuracy']:.1f}", fmt(x.get("wrong", 0))]
            L.append(" & ".join(cells) + r" \\")
            v = f"{100 * row['violate']:.0f}"
            for pol in ("safe", "majority", "naive"):
                tag = {"0": "Zero", "10": "Ten", "25": "Quarter", "50": "Half"}.get(v, v)
                N[f"sens{pol}{tag}Acc"] = f"{100 * row[pol]['accuracy']:.1f}"; N[f"sens{pol}{tag}Cov"] = fmt(100 * row[pol]["coverage"])
                N[f"sens{pol}{tag}Wrong"] = fmt(row[pol].get("wrong", 0))
        open(os.path.join(a.out, "tab_sens.tex"), "w").write("\n".join(L) + "\n")
        N["sensSeeds"] = len(sens["seeds"])

    # ── RQ5 ──
    if rep:
        env = rep["safe"]["per_key"].get("environment", {})
        N["rqFivesafeEnvCorrect"] = fmt(env.get("correct", 0))
        for pol in ("naive", "safe"):
            x = rep[pol]["all"]
            N["rqFive" + pol + "Findings"] = fmt(x["findings"]); N["rqFive" + pol + "Proposed"] = fmt(x.get("proposed", 0))
            N["rqFive" + pol + "Correct"] = fmt(x.get("correct", 0)); N["rqFive" + pol + "Wrong"] = fmt(x.get("wrong", 0))
            N["rqFive" + pol + "Acc"] = fmt(100 * x.get("correct", 0) / max(1, x.get("proposed", 0)))
            N["rqFive" + pol + "Cov"] = fmt(100 * x.get("proposed", 0) / max(1, x["findings"]))
            dc = rep[pol]["per_key"].get("data-classification", {})
            N["rqFive" + pol + "DCWrong"] = fmt(dc.get("wrong", 0)); N["rqFive" + pol + "DCProposed"] = fmt(dc.get("proposed", 0))
    if loop:
        p = loop["params"]
        N["loopAccept"] = fmt(100 * p["accept"]); N["loopAnswer"] = fmt(100 * p["answer"])
        N["loopReread"] = fmt(100 * p["reread"]); N["loopDrift"] = fmt(100 * p["drift"]); N["loopRoleAt"] = p["new_role_at"]
        runs = loop["runs"]
        ncyc = len(runs["safe"][0])
        N["loopSeeds"] = len(runs["safe"]); N["loopCycles"] = ncyc
        L = []
        for c in [x for x in (0, 3, 4, ncyc - 1) if x < ncyc]:
            cells = [str(c)]
            for pol in ("safe", "naive"):
                xs = [h[c] for h in runs[pol]]
                m = lambda key: statistics.mean(x[key] for x in xs)
                cells += [fmt(m("open_errors")), fmt(100 * m("compliant") / m("in_scope")),
                          fmt(100 * m("correct") / m("in_scope")), fmt(m("silent_wrong_values"))]
            L.append(" & ".join(cells) + r" \\")
        open(os.path.join(a.out, "tab_loop.tex"), "w").write("\n".join(L) + "\n")
        endc = ncyc - 1
        rat = loop["params"]["new_role_at"]
        for pol in ("safe", "naive"):
            m_ = lambda c: statistics.mean(h[c]["open_errors"] for h in runs[pol])
            N["loop" + pol + "CloseA"] = fmt(100 * (1 - m_(3) / m_(0)))
            if rat + 3 < ncyc:
                N["loop" + pol + "CloseB"] = fmt(100 * (1 - m_(rat + 3) / m_(rat)))
        for pol in ("safe", "naive"):
            xs = [h[endc] for h in runs[pol]]
            N["loop" + pol + "Silent"] = fmt(statistics.mean(x["silent_wrong_values"] for x in xs))
            N["loop" + pol + "Correct"] = fmt(100 * statistics.mean(x["correct"] / x["in_scope"] for x in xs))
            N["loop" + pol + "Compliant"] = fmt(100 * statistics.mean(x["compliant"] / x["in_scope"] for x in xs))

    # ── ontology metrics (docs/metrics.json, written by tools/onto_doc.py) ──
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    mp = os.path.join(here, "docs", "metrics.json")
    if os.path.exists(mp):
        om = json.load(open(mp))
        for k, tag in (("classes", "Classes"), ("defined_classes", "Defined"), ("object_properties", "Obj"),
                       ("datatype_properties", "Data"), ("property_chains", "Chains"), ("transitive_properties", "Trans"),
                       ("functional_properties", "Func"), ("disjointness_axioms", "Disj"), ("tbox_org_triples", "Triples"),
                       ("resource_types", "Types"), ("basekinds", "BaseKinds"), ("functional_categories", "Cats")):
            N["ont" + tag] = fmt(om[k])

    with open(os.path.join(a.out, "numbers.tex"), "w") as f:
        f.write("% generated by eval/make_tables.py -- do not edit\n")
        W = dict(zip("0123456789", ["Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"]))
        for k, v in sorted(N.items()):
            k = "".join(W.get(c, c) for c in k)
            f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
    print(f"{len(N)} numbers")


if __name__ == "__main__":
    main()
