#!/usr/bin/env bash

set -e

fuzzTime=${1:-10}

files=$(grep -r --include='**_test.go' --files-with-matches 'func Fuzz' .)

for file in ${files}
do
    funcs=$(grep -oP 'func \K(Fuzz\w*)' $file)
    for func in ${funcs}
    do
        echo "Fuzzing $func in $file"
        parentDir=$(dirname $file)
        go test $parentDir -run=$func -fuzz=$func$ -fuzztime=${fuzzTime}s -tags sync,metrics,search,scrub,containers_image_openpgp | grep -oP -x '^(?:(?!\blevel\b).)*$'
    done
done
