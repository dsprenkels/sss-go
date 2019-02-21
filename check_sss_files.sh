#!/bin/bash

basedir="$(dirname $0)"
files=(	
	"sss.h"
	"sss.c"
	"hazmat.h"
	"hazmat.c"
	"randombytes.h"
	"randombytes.c"
	"tweetnacl.h"
	"tweetnacl.c"
)

for file in "${files[@]}"; do
	if [[ "$(sha256sum "$basedir/$file" | head -c 64)" != "$(sha256sum "$basedir/sss/$file" | head -c 64)" ]]; then
		echo "ERROR: Files did not match: $file"
		exit 1
	fi
done
