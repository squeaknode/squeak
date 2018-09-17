#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from setuptools import find_packages
from setuptools import setup

from src.squeak import __version__

setup(
    name='squeaklib',
    version=__version__,
    license='MIT',
    author='Jonathan Zernik',
    description='Squeak library',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    packages=find_packages('src'),
    package_dir={'': 'src'},
    zip_safe=False,
    keywords=[
        'squeak',
    ],
    install_requires=[
        "cryptography",
        "python-bitcoinlib",
    ],
)
