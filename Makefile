.PHONY: all install lint test live-test build clean minify-js minify-css minify

SRC=server.py passzero/*.py
JS_SRC=static/js/*.js
UNIT_TEST_SRC=tests/unit_tests/*.py
E2E_TEST_SRC=tests/end_to_end_tests/*.py
CWD=$(shell pwd)

js_targets := $(patsubst static/js/src/%.js,static/js/dist/%.min.js,$(wildcard static/js/src/*.js))
css_targets := $(patsubst static/css/src/%.css,static/css/dist/%.min.css,$(wildcard static/css/src/*.css))

all: lint test build

install: package.json
	npm install
	cp -R node_modules/* static/lib

build: build/add_build_name.py passzero/config.py
	python build/add_build_name.py passzero/config.py

minify: minify-js minify-css

minify-js: $(js_targets)

static/js/dist/%.min.js: static/js/src/%.js
	uglifyjs $< -o $@

minify-css: $(css_targets)

static/css/dist/%.min.css: static/css/src/%.css
	cleancss $< >$@

test: $(SRC) $(UNIT_TEST_SRC) lint
	PYTHONPATH=$(CWD) pytest $(UNIT_TEST_SRC)

test-cov: $(SRC) $(UNIT_TEST_SRC) lint
	PYTHONPATH=$(CWD) pytest --cov=passzero --cov-report=html $(UNIT_TEST_SRC)

live-test: $(SRC) $(E2E_TEST_SRC) lint
	PYTHONPATH=$(CWD) pytest $(E2E_TEST_SRC)

lint: $(SRC) $(JS_SRC)
	jshint $(JS_SRC)
	pyflakes $(SRC) $(UNIT_TEST_SRC) $(E2E_TEST_SRC)

clean:
	find . -name '*.pyc' -delete
