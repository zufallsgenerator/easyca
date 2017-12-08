#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

for file in $DIR/clitests/test_*; do
    [ -f "$file" ] && [ -x "$file" ] && "$file"
done
