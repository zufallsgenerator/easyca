SHELL := /bin/bash
.PHONY: clitest pytest test 

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
