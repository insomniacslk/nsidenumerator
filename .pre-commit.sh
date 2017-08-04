#!/bin/bash

exec 1>&2

FILES=$(git diff --name-only HEAD)
for file in $FILES
do
    extension="${file##*.}"
    if [ "x$extension" = "xpy" ]; then
        mypy --ignore-missing-imports "$file" || (echo "mypy failed on $file" ; exit 1)
    elif [ "x$extension" = "xgo" ]; then
        gofmt "$file"
    fi
done

