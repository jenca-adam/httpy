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
The commands are as follows:

#### `make black`

Runs a linter.

#### `make docs`

Runs Sphinx, see [Documentation](#documentation)

#### `make setup`

Installs `make_reqs.txt`
This command should be run before anything else

#### `make tests`
 
