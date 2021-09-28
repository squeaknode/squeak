#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from setuptools import find_packages
from setuptools import setup

from squeak import __version__

setup(
    name='squeakpy',
    version=__version__,
    author='Jonathan Zernik',
    description='Squeak library',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    packages=find_packages(exclude=["tests*"]),
    zip_safe=True,
    keywords=[
        'squeak',
    ],
    install_requires=[
        "cryptography>=3.3.0,<3.5",
        "python-bitcoinlib>=0.11.0,<0.12",
        "ECPy>=1.2.0,<1.3",
    ],
)
