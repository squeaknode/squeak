all: test

clean:
	rm -rf build dist *.egg-info/ .tox/
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete

test:
	tox
	tox -e codechecks

coverage:
	tox -e coverage

mypy:
	tox -e mypy

.PHONY: all clean test coverage
