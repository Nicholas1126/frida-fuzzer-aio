#!/bin/bash

set -e
echo "HAL 9000" | $@ -o tmp/uniq-%n -n 100 -p od -m num 
md5cmd=$(test -x "$(which md5)" && echo "md5 -r" || echo "md5sum")
test 0 = $($md5cmd tmp/uniq-* | sed -e 's/ .*//' | sort | uniq -c | grep -v " 1 " | wc -l)
rm tmp/uniq-*
