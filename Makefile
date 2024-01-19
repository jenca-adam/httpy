PYTHON=/usr/bin/python
BLACK_CMD=$(PYTHON) -m black . -v --exclude="($(dir)docs/httpy/|$(dir)docs/source/httpy/|$(dir)tests/httpy/)"
DOCS_DIR=./docs
DOCS_MAKEARGS=html
MAKE=make
DIST=./dist
BUILD=./build
SETUP_PY=./setup.py
SETUP_PYARGS=sdist bdist bdist_wheel
TESTDIR=./tests
SPHINX_APIDOC=sphinx-apidoc
BADGES=./\.badges.rst
DOCS_INDEX=./docs/source/index.rst
DOCS_FILES=./docs/source/index.rst ./docs/source/modules.rst ./docs/source/httpy.rst
HTTPY_SOURCE=./httpy
REQUIREMENTS=requirements.txt -r make_requirements.txt
ALL_DIST=./all_dist
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
setup:  $(REQUIREMENTS)
	pip install -r $(REQUIREMENTS)
build:  $(SETUP_PY)
	rm -rf $(DIST) $(BUILD) 
	$(PYTHON) $(SETUP_PY) $(SETUP_PYARGS)
	for file in $(DIST)/* ; do \
		cp -f $$file $(ALL_DIST); \
	done
	rm -rf $(BUILD)
