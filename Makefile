.PHONY: clitest pytest test 

clitest:
	./run_clitests.bash
	

pytest:
	python setup.py test

test: clitest pytest
