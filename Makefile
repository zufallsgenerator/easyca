SHELL := /bin/bash
.PHONY: clitest pytest test
.PHONY: ubuntu-shell


clitest:
	./run_clitests.bash

pytest:
	python setup.py test

clean:
	find . | grep -E "(__pycache__|\.pyc|\.pyo$\)" | xargs rm -rf
	rm -rf build
	rm -rf dist
	rm -rf *.egg-info

test: clitest pytest

ubuntu-shell:
	docker run -v ${PWD}:/usr/src/app -i -t easycatest:latest /bin/bash


.PHONY: buildimage
buildimage:
	docker build -t easycatest .

