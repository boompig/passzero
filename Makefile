.PHONY: all clean

all:
	jshint static/js/*.js
	pyflakes *.py
	export PYTHONPATH=$(shell pwd)
	nosetests test/backend_correctness.py
	nosetests test/api_v1_test.py
	python build/add_build_name.py config.py

clean:
	rm *.pyc
