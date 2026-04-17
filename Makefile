SHELL := /bin/bash

.PHONY: help

help:
	@echo "Usage: make <session>.svg"
	@echo
	@echo "Builds Graphviz output from artifacts/coord-monitor/live/<session>/raw/*.log"
	@echo "and writes the rendered SVG to:"
	@echo "  artifacts/coord-monitor/live/<session>/post/graph/combined.svg"

%.svg:
	@session="$*"; \
	raw_dir="artifacts/coord-monitor/live/$$session/raw"; \
	post_dir="artifacts/coord-monitor/live/$$session/post"; \
	if ! compgen -G "$$raw_dir/*.log" > /dev/null; then \
		echo "No raw coord-monitor logs found for session '$$session' in $$raw_dir" >&2; \
		exit 1; \
	fi; \
	python3 testing/lib/coord_monitor.py \
		--run-dir "$$post_dir" \
		--run-id "$${session}_post" \
		--topology "$$session" \
		--from-raw $$raw_dir/*.log; \
	dot -Tsvg "$$post_dir/graph/combined.dot" -o "$$post_dir/graph/combined.svg"; \
	echo "Built $$post_dir/graph/combined.svg"
