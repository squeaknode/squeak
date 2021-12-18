all: test

clean:
	rm -rf build dist *.egg-info/ .tox/
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete

test:
	tox

.PHONY: all clean test
