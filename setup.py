#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from setuptools import find_packages
from setuptools import setup

setup(
    name='squeaklib',
    version='0.1.0',
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
    install_requires=[],
)
