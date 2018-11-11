#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from setuptools import find_packages
from setuptools import setup

from squeak import __version__

setup(
    name='squeaklib',
    version=__version__,
    author='Jonathan Zernik',
    description='Squeak library',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    packages=find_packages(exclude=["tests*"]),
    zip_safe=False,
    keywords=[
        'squeak',
    ],
    install_requires=[
        "cryptography",
        "python-bitcoinlib",
    ],
)
