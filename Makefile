.PHONY: all install lint test build clean

SRC=passzero/*.py
JS_SRC=static/js/*.js
UNIT_TEST_SRC=tests/unit_tests/*.py
CWD=$(shell pwd)

all: lint test build

install: package.json
	npm install
	cp -R node_modules/* static/lib

build: build/add_build_name.py passzero/config.py
	python build/add_build_name.py passzero/config.py

test: $(SRC) $(UNIT_TEST_SRC)
	PYTHONPATH=$(CWD) pytest $(UNIT_TEST_SRC)

lint: $(SRC) $(JS_SRC)
	jshint $(JS_SRC)
	pyflakes $(SRC) $(UNIT_TEST_SRC)

clean:
	find . -name '*.pyc' -delete
