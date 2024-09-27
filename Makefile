PYTHON=/usr/bin/python3
BLACK_CMD=$(PYTHON) -m black . -v --exclude="($(dir)docs/httpy/|$(dir)docs/source/httpy/|$(dir)tests/httpy/)"
DOCS_DIR=./docs
DOCS_MAKEARGS=html
MAKE=make
DIST=./dist
BUILD=./build
BUILD_MODULE=-m build
BUILD_MODULE_ARGS=--sdist --wheel
TESTDIR=./tests
LATEST=./latest_release/latest.whl
SPHINX_APIDOC=sphinx-apidoc
BADGES=./\.badges.rst
DOCS_INDEX=./docs/source/index.rst
DOCS_FILES=./docs/source/index.rst ./docs/source/modules.rst ./docs/source/httpy.rst
HTTPY_SOURCE=./src/httpy
REQUIREMENTS=requirements.txt 
MAKE_REQS=make_reqs.txt
ALL_DIST=./all_dist
PYPROJECT_TOML=pyproject.toml
SRC=./src
all: black docs
black:
	$(BLACK_CMD)
docs: $(DOCS_MAKEFILE) $(HTTPY_SOURCE) $(DOCS_FILES) $(PANDOC)
	$(SPHINX_APIDOC) $(HTTPY_SOURCE) -o $(DOCS_DIR)/source 
	cd $(DOCS_DIR) && $(MAKE) $(DOCS_MAKEARGS)
	-cat <$(BADGES) >README.rst; cat $(DOCS_INDEX) >>README.rst
test:
	cd $(TESTDIR); \
		bash ./run_all.sh
setup:  $(REQUIREMENTS) $(MAKE_REQS)
	pip install -r $(REQUIREMENTS) -r $(MAKE_REQS)
build:  $(PYPROJECT_TOML)
	rm -rf $(DIST) $(BUILD) 
	$(PYTHON) $(BUILD_MODULE) $(BUILD_MODULE_ARGS)
	for file in $(DIST)/* ; do \
		cp -f $$file $(ALL_DIST); \
	done
	cp $(DIST)/*.whl $(LATEST) # BADGE FIX
	rm -rf $(BUILD)
	rm -rf $(SRC)/*.egg-info
upload: $(DIST)/*
	twine upload $(DIST)/*

