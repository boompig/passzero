.PHONY: all install lint test live-test build clean minify-js minify-css minify copy-deps ts-compile

SRC=server.py passzero/*.py
UNIT_TEST_SRC=tests/unit_tests/*.py
E2E_TEST_SRC=tests/end_to_end_tests/*.py
CWD=$(shell pwd)

js_src := static/js/src/*.js
css_src := static/css/src/*.css
js_targets := $(patsubst static/js/src/%.js, static/js/dist/%.min.js, $(wildcard static/js/src/*.js))
css_targets := $(patsubst static/css/src/%.css, static/css/dist/%.min.css,$(wildcard static/css/src/*.css))
js_src_targets := $(patsubst typescript/%.ts, static/js/src/%.js, $(wildcard typescript/*.ts))

uglifyjs := node_modules/uglify-js/bin/uglifyjs
csslint  := node_modules/csslint/dist/cli.js
cleancss := node_modules/clean-css-cli/bin/cleancss
tsc		 := node_modules/typescript/bin/tsc

all: lint test build

install: package.json
	yarn
	make copy-deps

build: build/add_build_name.py passzero/config.py
	python build/add_build_name.py passzero/config.py

minify: minify-js minify-css

copy-deps: node_modules
	mkdir -p static/lib
	cp -R node_modules/* static/lib/

ts-compile: $(js_src_targets)

static/js/src/%.js: typescript/%.ts
	$(tsc) --outFile $@ $<

minify-js: ts-compile $(js_targets)

static/js/dist/%.min.js: static/js/src/%.js
	mkdir -p static/js/dist
	$(uglifyjs) $< -o $@

minify-css: $(css_targets)

static/css/dist/%.min.css: static/css/src/%.css
	mkdir -p static/css/dist
	$(cleancss) $< >$@

test: $(SRC) $(UNIT_TEST_SRC) lint
	PYTHONPATH=$(CWD) pytest $(UNIT_TEST_SRC)

test-cov: $(SRC) $(UNIT_TEST_SRC) lint
	PYTHONPATH=$(CWD) pytest --cov=passzero --cov=server --cov-report=html $(UNIT_TEST_SRC)

live-test-local: $(SRC) $(E2E_TEST_SRC) lint
	PYTHONPATH=$(CWD) LIVE_TEST_HOST='https://localhost:5050' pytest tests/end_to_end_tests/api_v1_test.py

live-test-prod: $(SRC) $(E2E_TEST_SRC) lint
	PYTHONPATH=$(CWD) LIVE_TEST_HOST='https://passzero.herokuapp.com' pytest tests/end_to_end_tests/api_v1_test.py

lint: $(SRC) $(css_src) $(js_src)
	jshint $(js_src)
	csslint --quiet --config=.csslintrc $(css_src)
	pyflakes $(SRC) $(UNIT_TEST_SRC) $(E2E_TEST_SRC)

clean:
	find . -name '*.pyc' -delete
