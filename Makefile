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
BADGES=./\.badges.md
DOCS_INDEX=./docs/source/index.rst
DOCS_FILES=./docs/source/index.rst ./docs/source/modules.rst ./docs/source/httpy.rst
HTTPY_SOURCE=./httpy
REQUIREMENTS=requirements.txt -r make_requirements.txt
PANDOC=/usr/bin/pandoc
ALL_DIST=./all_dist
PANDOC_FLAGS=--verbose -s -o
all: black docs
black:
	$(BLACK_CMD)
docs: $(DOCS_MAKEFILE) $(HTTPY_SOURCE) $(DOCS_FILES) $(PANDOC)
	cd $(DOCS_DIR) && $(MAKE) $(DOCS_MAKEARGS)
	-ln -s $(DOCS_INDEX) README.rst
	-$(PANDOC) $(PANDOC_FLAGS) tmp.md README.rst
	-cat <$(BADGES) >README.md; cat tmp.md >>README.md; rm tmp.md
	
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
