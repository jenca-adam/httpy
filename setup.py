"""setup.py"""

import sys
import setuptools

PROJECT_URLS = {
    "GitHub": "https://github.com/jenca-adam/httpy",
    "PyPI": "https://pypi.python.org/project/httpy",
    "Bug Tracker": "https://github.com/jenca-adam/httpy/issues",
    "Download": "https://github.com/jenca-adam/httpy/releases/latest",
}

try:
    ld = open("README.rst").read()
except:
    ld = ""


class VersionError(Exception):
    """Raised if vrong wersion"""


if sys.hexversion < 0x3060000:
    raise VersionError(
        "Wrong version number, need at least python3.6.0. Currently in use : "
        + sys.version
    )

setuptools.setup(
    name="httpy",
    author="Adam Jenca",
    description="A lightweight socket-based HTTP(s) and WebSocket client.",
    long_description=ld,
    version="2.0.1",
    long_description_content_type="text/x-rst",
    packages=["httpy", "httpy.http2", "httpy.http2.hpack", "httpy.http2.hpack.static", "httpy.http2.hpack.utils"],
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
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Topic :: Internet :: WWW/HTTP",
        "Environment :: Web Environment",
    ],
    python_requires=">=3.6.0",
)
