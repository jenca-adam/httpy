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

*  `README.md`,`README.rst`

   see [Documentation](#documentation)

* `requirements.txt`
