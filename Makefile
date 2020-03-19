.PHONY: all install lint test live-test-local build-name clean minify-js minify-css minify ts-compile

SRC=server.py passzero/*.py passzero/api/*.py passzero/models/*.py
UNIT_TEST_SRC=tests/unit_tests/*.py
E2E_TEST_SRC=tests/end_to_end_tests/*.py
CWD=$(shell pwd)

css_src 		:= static/css/src/*.css
standalone_typescript_src := typescript/standalone/*.ts
css_targets 	:= $(patsubst static/css/src/%.css, static/css/dist/%.min.css, $(wildcard static/css/src/*.css))
js_src_targets 	:= $(patsubst typescript/standalone/%.ts, static/js/src/standalone/%.js, $(wildcard typescript/standalone/*.ts)) $(patsubst typescript/common/%.ts, static/js/src/common/%.js, $(wildcard typescript/common/*.ts))
js_dist_targets := $(patsubst typescript/standalone/%.ts, static/js/dist/%.min.js, $(wildcard typescript/standalone/*.ts)) $(patsubst typescript/common/%.ts, static/js/dist/%.min.js, $(wildcard typescript/common/*.ts))

csslint  := node_modules/csslint/dist/cli.js
uglifyjs := node_modules/uglify-js/bin/uglifyjs
cleancss := node_modules/clean-css-cli/bin/cleancss

all: lint test build-name

install: package.json
	yarn

build-name: scripts/add_build_name.py passzero/config.py
	python scripts/add_build_name.py passzero/config.py

minify: minify-js minify-css

ts-compile: $(standalone_typescript_src) typescript/standalone/tsconfig.json
	mkdir -p static/js/src
	# use the standalone tsconfig.json file for this
	yarn run tsc --project typescript/standalone/

minify-js: ts-compile $(js_dist_targets)

static/js/dist/%.min.js: static/js/src/**/%.js
	mkdir -p static/js/dist
	$(uglifyjs) $< -o $@

static/js/src/standalone/%.js: $(standalone_typescript_src) ts-compile
static/js/src/common/%.js: $(standalone_typescript_src) ts-compile

minify-css: $(css_targets)

static/css/dist/%.min.css: static/css/src/%.css
	mkdir -p static/css/dist
	$(cleancss) $< >$@

test: python-test

python-test: $(SRC) $(UNIT_TEST_SRC) lint
	# run until only first failure to not waste time
	PYTHONPATH=$(CWD) pytest -x tests/unit_tests

test-cov: $(SRC) $(UNIT_TEST_SRC) lint
	PYTHONPATH=$(CWD) pytest --cov=passzero --cov-report=html tests/unit_tests

live-test-local: $(SRC) $(E2E_TEST_SRC) lint
	# use heroku local to make extra certain everything works
	PYTHONPATH=$(CWD) LIVE_TEST_HOST='https://localhost:5100' pytest tests/end_to_end_tests

lint: $(SRC) $(standalone_typescript_src) $(css_src)
	$(csslint) --quiet $(css_src)
	yarn lint
	flake8 $(SRC) tests/unit_tests tests/end_to_end_tests
	mypy --ignore-missing-imports $(SRC)
	mypy --ignore-missing-imports tests/unit_tests tests/end_to_end_tests

clean:
	find . -name '*.pyc' -delete
	rm -f $(js_src_targets) $(js_dist_targets) $(css_targets)
	# remove auto-generated minified code
	rm -f static/js/dist/*
	rm -f static/css/dist/*
	# remove auto-generated typescript code
	rm -rf static/js/src/*
