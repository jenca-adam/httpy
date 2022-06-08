'''setup.py module'''
import sys
import setuptools

class VersionError(Exception):
    '''Raised if vrong wersion'''


if sys.hexversion < 0x3060000:
    raise VersionError(
        "Wrong version number, need at least python3.6.0. Currently in use : "
        + sys.version
    )

setuptools.setup(
    name="httpy",
    author="Adam Jenca",
    description="Lightweight socket-based HTTP(s) and WebSocket client.",
    long_description="""
A lightweight socket-based library to create HTTP(s) and WebSocket connections.
## Features
   * Cookies support
   * Caching support
   * Easy debugging
   * HTTP authentication
   * Form support
   * No requirements(save Python)
   * Keep-Alive and connection pooling
## License
    GPLv3
Docs at <https://httpy.readthedocs.io/>""",
    version="1.2.1",
    long_description_content_type="text/markdown",
    packages=["httpy"],
    author_email="jenca.a@gjh.sk",
    url="https://github.com/jenca-adam/httpy",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Topic :: Internet :: WWW/HTTP",
        "Environment :: Web Environment",
    ],
    python_requires=">=3.6.0",
)
