#!/bin/bash

rm docs/build/text/index.txt
sphinx-build -M text docs/source docs/build

cat header.rst docs/build/text/index.txt > README.rst