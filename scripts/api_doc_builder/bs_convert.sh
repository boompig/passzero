#!/bin/bash

for fname in templates/api_v1_docs/*.html
do
	python "utils/api_doc_builder/compare_docs.py" "$fname" > "/tmp/$(basename $fname).real"
done

echo 'done'
