.PHONY: all clean

all:
	jshint static/js/*.js
	pyflakes *.py
	python api_test.py
	nosetests test/backend_correctness.py
	python build/add_build_name.py config.py

clean:
	rm *.pyc
