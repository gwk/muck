# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

# $@: The file name of the target of the rule.
# $<: The name of the first prerequisite.
# $^: The names of all the prerequisites, with spaces between them.
# $*: The stem with which a pattern rule matches.


.PHONY: _default clean cov docs lib pip-develop pip-uninstall pypi-dist pypi-upload test typecheck

# First target of a makefile is the default.
_default: test typecheck

clean:
	rm -rf _build/* muck/libmuck.*.so

cov:
	iotest -fail-fast -coverage

docs:
	(cd doc && muck publish index.html dev-setup.html -to=../docs)
	writeup -bare -section Muck doc/index.html.wu readme.md

	(cd demos/oecd-health && muck publish -to=../../docs/demos/oecd-health)
	#writeup -bare -section 0 demos/oecd-health/{index.html.wu,readme.md}

help: # Summarize the targets of this makefile.
	@GREP_COLOR="1;32" egrep --color=always '^\w[^ :]+:' makefile | sort


lib-check:
	clang -fsyntax-only \
	-Weverything \
	-Wno-gnu-zero-variadic-macro-arguments \
	-Wno-gnu-empty-initializer \
	-Wno-unused-function \
	muck/libmuck.c


pip-dev: lib-check
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
	craft-py-check muck pithy/pithy -deps pithy writeup
