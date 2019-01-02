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
js_test_src 	:= tests/angular/*.js
entries_bundle_src := typescript/entries-bundle/*.tsx typescript/entries-bundle/components/*.tsx

csslint  := node_modules/csslint/dist/cli.js
uglifyjs := node_modules/uglify-js/bin/uglifyjs
cleancss := node_modules/clean-css-cli/bin/cleancss

all: lint test build-name

install: package.json
	yarn

build-name: scripts/add_build_name.py passzero/config.py
	python scripts/add_build_name.py passzero/config.py

minify: minify-js minify-css

static/js/dist/entries.bundle.js: $(entries_bundle_src)
	yarn run webpack

ts-compile: $(standalone_typescript_src) typescript/standalone/tsconfig.json
	mkdir -p static/js/src
	# use the standalone tsconfig.json file for this
	yarn run tsc --project typescript/standalone/

minify-js: ts-compile $(js_dist_targets) static/js/dist/entries.bundle.js

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
	PYTHONPATH=$(CWD) pytest -x $(UNIT_TEST_SRC)

test-cov: $(SRC) $(UNIT_TEST_SRC) lint
	PYTHONPATH=$(CWD) pytest --cov=passzero --cov-report=html $(UNIT_TEST_SRC)

live-test-local: $(SRC) $(E2E_TEST_SRC) lint
	PYTHONPATH=$(CWD) LIVE_TEST_HOST='https://localhost:5050' pytest $(E2E_TEST_SRC)

lint: $(SRC) $(standalone_typescript_src) $(css_src)
	$(csslint) --quiet $(css_src)
	yarn lint
	flake8 $(SRC) $(UNIT_TEST_SRC) $(E2E_TEST_SRC)

clean:
	find . -name '*.pyc' -delete
	rm -f $(js_src_targets)
	# remove auto-generated minified code
	rm -f static/js/dist/*.js
	rm -f static/css/dist/*.css
	# remove auto-generated typescript code
	rm -f static/js/src/*.js
