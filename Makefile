.PHONY: all install lint test live-test-local build-name clean minify-js minify-css minify ts-compile

SRC=server.py passzero/*.py
UNIT_TEST_SRC=tests/unit_tests/*.py
E2E_TEST_SRC=tests/end_to_end_tests/*.py
CWD=$(shell pwd)

css_src 		:= static/css/src/*.css
js_dist_targets := $(patsubst typescript/%.ts, static/js/dist/%.min.js, $(wildcard typescript/*.ts))
css_targets 	:= $(patsubst static/css/src/%.css, static/css/dist/%.min.css, $(wildcard static/css/src/*.css))
js_src_targets 	:= $(patsubst typescript/%.ts, static/js/src/%.js, $(wildcard typescript/*.ts))
js_test_src 	:= tests/angular/*.js

csslint  := node_modules/csslint/dist/cli.js
uglifyjs := node_modules/uglify-js/bin/uglifyjs
cleancss := node_modules/clean-css-cli/bin/cleancss
tsc		 := node_modules/typescript/bin/tsc

all: lint test build-name

install: package.json
	yarn

build-name: scripts/add_build_name.py passzero/config.py
	python scripts/add_build_name.py passzero/config.py

minify: minify-js minify-css

ts-compile: $(js_src_targets)

static/js/src/%.js: typescript/%.ts
	mkdir -p static/js/src
	$(tsc) $< --outDir static/js/src --module none

minify-js: ts-compile $(js_dist_targets)

static/js/dist/%.min.js: static/js/src/%.js
	mkdir -p static/js/dist
	$(uglifyjs) $< -o $@

minify-css: $(css_targets)

static/css/dist/%.min.css: static/css/src/%.css
	mkdir -p static/css/dist
	$(cleancss) $< >$@

test: python-test
	
python-test: $(SRC) $(UNIT_TEST_SRC) lint
	PYTHONPATH=$(CWD) pytest $(UNIT_TEST_SRC)
	
test-cov: $(SRC) $(UNIT_TEST_SRC) lint
	PYTHONPATH=$(CWD) pytest --cov=passzero --cov-report=html $(UNIT_TEST_SRC)

live-test-local: $(SRC) $(E2E_TEST_SRC) lint
	PYTHONPATH=$(CWD) LIVE_TEST_HOST='https://localhost:5050' pytest $(E2E_TEST_SRC)

lint: $(SRC) $(js_src_targets) $(css_src)
	$(csslint) --quiet $(css_src)
	yarn lint
	pyflakes $(SRC) $(UNIT_TEST_SRC) $(E2E_TEST_SRC)

clean:
	find . -name '*.pyc' -delete
	rm -f $(js_src_targets)
	# remove auto-generated minified code
	rm -f static/js/dist/*.js
	rm -f static/css/dist/*.css
	# remove auto-generated typescript code
	rm -f static/js/src/*.js
