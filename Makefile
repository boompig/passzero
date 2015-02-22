.PHONY: all clean

all:
	jshint static/js/*.js
	pyflakes *.py
	python build/add_build_name.py config.py

clean:
	rm *.pyc
