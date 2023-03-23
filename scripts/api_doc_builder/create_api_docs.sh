#!/bin/bash


program='scripts/api_doc_builder/create_api_docs.py'


#dest='/tmp/api_v1'
#rm -rf "$dest" || exit 1
#mkdir "$dest" || exit 1
#python "$program" passzero/api_v1.py api_v1 '/api/v1/' "$dest" || exit 1
#for f in "$dest"/*.html;
#do
	#base_fname="$(basename "$f")"
	#if [ -f "templates/api_v1_docs/$base_fname" ]; then
		#diff -q "$f" templates/api_v1_docs;
	#else
		#echo "WARNING: File templates/api_v1_docs/$base_fname does not exist"
	#fi
#done


dest='/tmp/api_v3/entry'
rm -rf "$dest" || exit 1
mkdir -p "$dest" || exit 1
python "$program" passzero/api/user.py foo '/api/v3/entry/' "$dest" \
	--output-format json || exit 1
for f in "$dest"/*.html;
do
	base_fname="$(basename "$f")"
	#if [ -f "templates/api_v1_docs/$base_fname" ]; then
		#diff -q "$f" templates/api_v1_docs;
	#else
		#echo "WARNING: File templates/api_v1_docs/$base_fname does not exist"
	#fi
done

