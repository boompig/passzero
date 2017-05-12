.PHONY: all install lint test build clean

SRC=passzero/*.py
JS_SRC=static/js/*.js
UNIT_TEST_SRC=tests/unit_tests/*.py

all: lint test build

install:
	npm install
	cp -R node_modules/* static/lib

build: build/add_build_name.py passzero/config.py
	python build/add_build_name.py passzero/config.py

test: $(SRC) $(UNIT_TEST_SRC)
	export PYTHONPATH=$(shell pwd)
	py.test $(UNIT_TEST_SRC)

lint: $(SRC) $(JS_SRC)
	jshint $(JS_SRC)
	pyflakes $(SRC)

clean:
	rm *.pyc
