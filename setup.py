#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -----------------------------------
#
# Name:       setup.py
# Purpose:
#
# Author:     engineer
#
# Created:    23 Oct 2016 2:02 PM
# Copyright:   (c) engineer 2016
# Licence:      MIT
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTUOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
# -----------------------------------
import sys

from setuptools import setup, find_packages, Extension

description = '''A python cli application for the chacha20 stream cipher'''

setup(
    name='chacha',
    description=description,
    author='nhallam',
    author_email='nhallam1@gmail.com',
    version='0.6a2',
    install_requires=['Click'],
    packages=find_packages(),
    py_modules=['cli'],
    entry_points='''
    [console_scripts]
    chacha=cli:cli
    ''',
    test_suite='tests',
)
