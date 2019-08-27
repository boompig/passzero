#!/bin/bash

src="$1"
dest="$2"

if [ -z "$src" ] || [ -z "$dest" ]
then
	echo "usage $0 src dest">&1
	exit 1
fi

for f in "$src"/*.html
do
	if ! cmp -s "$f" "$dest"/$(basename "$f")
	then
		cp -f -v "$f" "$dest"
	fi
done
