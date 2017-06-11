.PHONY: all install lint test live-test build clean minify-js minify-css minify copy-deps

SRC=server.py passzero/*.py
UNIT_TEST_SRC=tests/unit_tests/*.py
E2E_TEST_SRC=tests/end_to_end_tests/*.py
CWD=$(shell pwd)

js_src := static/js/src/*.js
js_targets := $(patsubst static/js/src/%.js,static/js/dist/%.min.js,$(wildcard static/js/src/*.js))
css_targets := $(patsubst static/css/src/%.css,static/css/dist/%.min.css,$(wildcard static/css/src/*.css))

uglifyjs := node_modules/uglify-js/bin/uglifyjs
cleancss := node_modules/clean-css-cli/bin/cleancss

all: lint test build

install: package.json
	npm install
	cp -R node_modules/* static/lib

build: build/add_build_name.py passzero/config.py
	python build/add_build_name.py passzero/config.py

minify: minify-js minify-css

copy-deps: node_modules
	mkdir -p static/lib
	cp -R node_modules/* static/lib/

minify-js: $(js_targets)

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
	PYTHONPATH=$(CWD) pytest --cov=passzero --cov-report=html $(UNIT_TEST_SRC)

live-test: $(SRC) $(E2E_TEST_SRC) lint
	PYTHONPATH=$(CWD) pytest $(E2E_TEST_SRC)

lint: $(SRC) $(js_src)
	jshint $(js_src)
	pyflakes $(SRC) $(UNIT_TEST_SRC) $(E2E_TEST_SRC)

clean:
	find . -name '*.pyc' -delete
