include .env
PACKAGE := x_auth
VPYTHON := $(VENV)/bin/python

.PHONY: all install pre-commit clean build twine patch

all:
	make install clean build

install: $(VENV)
	$(VENV)/bin/pip install .[dev]; make pre-commit
pre-commit: .pre-commit-config.yaml
	pre-commit install -t pre-commit -t post-commit -t pre-push

clean: dist $(PACKAGE).egg-info
	rm -rf dist/* $(PACKAGE).egg-info $(PACKAGE)/__pycache__ dist/__pycache__

build: $(VENV)
	$(VPYTHON) -m build; make twine
twine: $(VENV) dist
	$(VPYTHON) -m twine upload dist/* --skip-existing

patch: $(VENV)
	git tag `$(VPYTHON) -m setuptools_scm --strip-dev`; git push --tags --prune -f