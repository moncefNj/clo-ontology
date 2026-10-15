# Python 3.11+ and Java 8+ (HermiT). Pellet: see README (CLO_PELLET_PYTHON).
PY ?= python3
C7N ?= ../cloud-custodian
PAPER ?= ../paper
.PHONY: install test example demo catalogue ingest validate reproduce reproduce-fast tables
install:
	pip install -r requirements.txt
test:
	$(PY) tests/test_v8.py
	$(PY) tests/test_org.py
	$(PY) tests/test_v9.py
	$(PY) tests/test_cq.py
example:
	$(PY) tools/clo_audit.py --out-dir examples/company_audit
	$(PY) tools/clo_compile.py --in-dir examples/company_audit --out-dir examples/company_audit/enforce
	$(PY) tools/clo_viz.py --in-dir examples/company_audit --out examples/company_audit/clo_view.html
# CLO Studio: the interactive demonstrator (examples/demo/clo_studio.html, self-contained)
demo:
	$(PY) tools/clo_demo.py --out examples/demo/clo_studio.html
# Regenerate ontology/clo_types.ttl from a Fix Inventory checkout:  make catalogue FIX=../fixinventory
catalogue:
	$(PY) tools/extract_fixinventory_types.py --fix $(FIX) \
	  --clo ontology/clo_ontology_v8.ttl --curation data/labeling_support_curated.csv \
	  --out ontology/clo_types.ttl --report data/types_report.json
ingest:
	$(PY) tools/ingest_c7n.py --c7n $(C7N) --no-ext --out /tmp/c7n_noext.ttl --report data/open/c7n_ingest_report_noext.json
	$(PY) tools/ingest_c7n.py --c7n $(C7N) --out data/open/c7n_inventory.ttl \
	  --report data/open/c7n_ingest_report.json --json data/open/c7n_inventory.json
	$(PY) tools/extend_catalogue.py --inventory data/open/c7n_inventory.json --out ontology/clo_types_ext.ttl
# Witness check of the record-completeness rules on the Custodian fixtures
validate:
	$(PY) tools/validate_completeness.py --c7n $(C7N) --out results/rq2_completeness.json
reproduce:
	$(PY) eval/eval_rules.py --n 2000 --seeds 1 2 3 4 5 --out results/rq1_rules.json
	$(PY) eval/eval_rules.py --n 300 --seeds 1 2 --engine hermit --out results/rq1_hermit_with_conflicts.json
	$(PY) eval/eval_rules.py --n 300 --seeds 1 2 --engine hermit --single-type --out results/rq1_hermit.json
	$(PY) eval/real_data.py --inventory data/open/c7n_inventory.ttl --json data/open/c7n_inventory.json \
	  --out results/rq2_real.json --dl
	$(PY) tools/validate_completeness.py --c7n $(C7N) --out results/rq2_completeness.json
	$(PY) baselines/run_baselines.py --n 2000 --seeds 1 2 3 4 5 --out results/rq3_baselines.json
	$(PY) eval/engines.py --sizes 250 500 1000 --dl-max 2000 --rl-max 2000 --no-conflicts --out results/rq4_engines_dl.json
	$(PY) eval/engines.py --sizes 2000 --dl-max 2000 --rl-max 2000 --timeout 1800 --no-conflicts --out results/rq4_engines_dl.json
	$(PY) eval/conflicts.py --out results/rq4_conflicts.json
	$(PY) eval/engines.py --sizes 4000 8000 16000 32000 64000 --dl-max 0 --rl-max 0 --no-conflicts --out results/rq4_engines_scale.json
	$(PY) eval/e2e_scale.py --sizes 2000 4000 8000 16000 32000 64000 --out results/rq4_e2e.json
	$(PY) eval/eval_repairs.py --n 2000 --seeds 1 2 3 4 5 --out results/rq5_repairs.json
	$(PY) eval/repair_sensitivity.py --n 2000 --seeds 1 2 3 --levels 0 0.1 0.25 0.5 --out results/rq5_sensitivity.json
	$(PY) eval/loop.py --n 2000 --cycles 8 --seeds 1 2 3 --out results/rq5_loop.json
	$(PY) tools/clo_demo.py --out examples/demo/clo_studio.html
# Fast subset (minutes): everything except the HermiT/Pellet runs and the Custodian checkout
reproduce-fast:
	$(PY) eval/eval_rules.py --n 2000 --seeds 1 2 3 4 5 --out results/rq1_rules.json
	$(PY) eval/real_data.py --inventory data/open/c7n_inventory.ttl --json data/open/c7n_inventory.json \
	  --out results/rq2_real.json --keep-engines
	$(PY) baselines/run_baselines.py --n 2000 --seeds 1 2 3 4 5 --out results/rq3_baselines.json
	$(PY) eval/e2e_scale.py --sizes 2000 4000 8000 16000 32000 64000 --out results/rq4_e2e.json
	$(PY) eval/repair_sensitivity.py --n 2000 --seeds 1 2 3 --levels 0 0.1 0.25 0.5 --out results/rq5_sensitivity.json
	$(PY) eval/loop.py --n 2000 --cycles 8 --seeds 1 2 3 --out results/rq5_loop.json
	$(PY) tools/clo_demo.py --out examples/demo/clo_studio.html
tables:
	$(PY) eval/make_tables.py --results results --out $(PAPER)
