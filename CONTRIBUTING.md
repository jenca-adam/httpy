---
CONTRIBUTING.md
---

## Want to contribute?

Go right ahead!
But here are some thinks you need to know first:

### Project structure

* `docs/`
    
   The Sphinx documentation files.
   The most important file here is `docs/index.rst`. It contains the basic information about httpy.
   See [Documentation](#documentation) 

* `httpy/`
    
   The actual source code of the package. All the other directories named httpy are symlinks made for convenience.
   See [Code](#code)
    
   - `httpy/httpy.py`
        
        The "core" of the package: cookies, cache, main input methods and output classes.
    
   - `httpy/utils.py`

        Basically any generally useful function. Most of them are used from multiple files.

   - `httpy/alpn.py`

        ALPN implementation.

   - `httpy/errors.py`

        All the error classes used throughout HTTPy.

   - `httpy/status.py`

        HTTP status parser and accompanying data.
   
   - `httpy/debugger.py`

        A portable debugger implementation.
   
   - `httpy/http2`
        
        HTTP2 Implementation


* `tests/`
   
   HTTPy test directory.
   See [Testing](#testing)

* `dist/` `all_dist/`
    
   Built distributions.
   See [Building](#building)

*  `CONTRIBUTING.md`
    
   This file.
   You can edit this to improve its quality.

*  `LICENSE`

   The GNU GPL v3 license.
   You _can't_ edit it.

*  `Makefile`

   see [Makefile](#makefile)

*  `README.rst`

   see [Documentation](#documentation)

* `requirements.txt`

  A list of the project's requirements.
  Currently empty, but if your changes add a requirement, please add it to this file.

* `make_reqs.txt`

 A list of requirements needed to build the project (documentation tools, linters, etc.)

* `.badges.md`, `.badges.rst`

  see [Documentation](#documentation)

### Makefile

The `Makefile` contains a bunch of useful commands you might need when editing the project.
However, this only works on Linux. If you use Windows, you're on your own until someone adds more quality-of-life scripts.
The commands are as follows:

#### `make black`

Runs the code formatter.

#### `make docs`

Runs Sphinx, see [Documentation](#documentation)

#### `make setup`

Installs `make_reqs.txt`
This command should be run before anything else

#### `make test`

Runs tests, see [Testing](#testing)

#### `make build`

Builds the source distributions and wheels, see [Building](#building)

### Code quality

Please test your code thoroughly, as the test suite is quite lacking as of right now.
Also, don't write too inefficient / spaghetti code, as these problems can't be fixed by the formatter.

#### Code style

I don't really care, just pass it through the formatter, please

### Building

The latest source disribution is built into `dist/`.
Source dists for every version are in `all_dist/`.

Currently, the project is built using `setup.py`, although this might be changed to a more modern approach in the near future.

### Testing

Unit tests are in `tests/test_httpy.py`. These are written in `pytest`. Additional http2/async tests are in `tests/h2test`.
The test suite is severely lacking and does not cover nearly every aspect of the library, so you'll have to make a lot of makeshift
manual testing.

To run the tests, use the [Makefile](#makefile).
On Windows, run
```
python.exe -m h2tests
python.exe -m pytest test_httpy.py
```
in the `tests/` directory.

### Documentation

Documentation is built using `sphinx` and `sphinx-apidoc`, and hosted by https://readthedocs.io/ (https://httpy.readthedocs.io/)
To build the documentation, use `make docs`.
The README file is in `index.rst`. It contains the descriptions of high-level functions.
