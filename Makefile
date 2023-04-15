.PHONY: all install lint test live-test-local build-name clean minify-js minify ts-compile

SRC=server.py passzero/*.py passzero/api/*.py passzero/models/*.py
UNIT_TEST_SRC=tests/unit_tests/*.py
E2E_TEST_SRC=tests/end_to_end_tests/*.py
CWD=$(shell pwd)

common_typescript_src := typescript/common/*.ts
js_src_targets 	:= $(patsubst typescript/common/%.ts, static/js/src/common/%.js, $(wildcard typescript/common/*.ts))
js_dist_targets := $(patsubst typescript/common/%.ts, static/js/dist/%.min.js, $(wildcard typescript/common/*.ts))

uglifyjs := node_modules/uglify-js/bin/uglifyjs

all: lint test build-name

install: package.json
	yarn

build-name: scripts/add_build_name.py config/config.json
	python scripts/add_build_name.py config/config.json

minify: minify-js

ts-compile: $(common_typescript_src) typescript/common/tsconfig.json
	mkdir -p static/js/src
	# use the common tsconfig.json file for this
	yarn run tsc --project typescript/common/

minify-js: ts-compile $(js_dist_targets)

static/js/dist/%.min.js: static/js/src/%.js
	mkdir -p static/js/dist
	$(uglifyjs) $< -o $@

static/js/src/common/%.js: $(common_typescript_src) ts-compile

test: python-test

python-test: $(SRC) $(UNIT_TEST_SRC) python-lint
	# run until only first failure to not waste time
	PYTHONPATH=$(CWD) pytest -x tests/unit_tests

python-test-cov: $(SRC) $(UNIT_TEST_SRC) lint
	# run until only first failure to not waste time
	PYTHONPATH=$(CWD) pytest -x --cov=passzero --cov-report=html tests/unit_tests

live-test-local: $(SRC) $(E2E_TEST_SRC) lint
	# use heroku local to make extra certain everything works
	PYTHONPATH=$(CWD) LIVE_TEST_HOST='https://localhost:5100' pytest -x tests/end_to_end_tests

python-lint: $(SRC)
	flake8 $(SRC) tests/unit_tests tests/end_to_end_tests
	mypy --ignore-missing-imports --check-untyped-defs $(SRC)
	mypy --ignore-missing-imports tests/unit_tests
	mypy --ignore-missing-imports --check-untyped-defs tests/end_to_end_tests

js-lint: $(common_typescript_src)
	yarn lint

lint: python-lint js-lint

clean:
	find . -name '*.pyc' -delete
	rm -f $(js_src_targets) $(js_dist_targets)
	# remove auto-generated minified code
	rm -f static/js/dist/*
	# remove auto-generated typescript code
	rm -rf static/js/src/*
