#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from setuptools import find_packages
from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

requires = []

setup(
    name='squeak',
    version='0.1.0',
    license='MIT',
    author='Jonathan Zernik',
    description='Squeak network',
    long_description=long_description,
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
    install_requires=requires,
)
