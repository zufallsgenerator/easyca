#!/bin/bash

rm docs/build/rst/index.rst
sphinx-build -M rst docs/source docs/build -E -a

cat header.rst docs/build/rst/index.rst > README.rst
