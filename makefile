# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

# $@: The file name of the target of the rule.
# $<: The name of the first prerequisite.
# $^: The names of all the prerequisites, with spaces between them.


.PHONY: _default clean cov docs lib pip-develop pip-uninstall pypi-dist pypi-upload test typecheck

# First target of a makefile is the default.
_default: test typecheck

clean:
	rm -rf _build/* docs/* muck/libmuck.*.so

cov:
	iotest -fail-fast -coverage

docs:
	(cd doc && muck publish index.html dev-setup.html -to=../docs)
	writeup -bare -section Muck doc/index.html.wu readme.md

lib:
	clang -fsyntax-only \
	-Weverything \
	-Wno-gnu-zero-variadic-macro-arguments \
	-Wno-gnu-empty-initializer \
	-Wno-unused-function \
	muck/libmuck.c


pip-develop: lib
	pip3 install -e .

pip-install:
	pip3 install .

pip-uninstall:
	pip3 uninstall --yes muck

pypi-dist:
	python3 setup.py sdist

pypi-upload:
	python3 setup.py sdist upload

test:
	iotest -fail-fast

typecheck:
	craft-py-check muck
