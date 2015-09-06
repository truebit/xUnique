#!/usr/bin/env python
"""
This software is licensed under the Apache 2 license, quoted below.

Copyright 2014 Xiao Wang <wangxiao8611@gmail.com, http://fclef.wordpress.com/about>

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this file except in compliance with the License. You may obtain a copy of
the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
"""

try:
    from setuptools import setup
except ImportError:
    raise SystemExit('Please install "setuptools" module first.')

from os import path
from codecs import open as copen

here = path.dirname(path.abspath(__file__))
readme_path = path.join(here, 'README.rst')
with copen(readme_path, encoding='utf-8') as f:
    long_description = f.read()

__version__ = '4.1.1'

setup(
    name="xUnique",
    version=__version__,
    py_modules=['xUnique'],
    entry_points = {
        'console_scripts' : [ 'xunique=xUnique:main' ],
    },
    description='A converter of the Xcode project file to make merging it much easier in VCS',
    long_description=long_description,
    author='Xiao Wang',
    author_email='wangxiao8611@gmail.com',
    url='https://github.com/truebit/xUnique',
    license='Apache License, Version 2.0',
    keywords=['Xcode project file', 'pbxproj', 'resolve merge conflict'],
    classifiers=['Development Status :: 5 - Production/Stable',
                 'Intended Audience :: Developers',
                 'License :: OSI Approved :: Apache Software License',
                 'Topic :: Software Development :: Build Tools',
                 'Topic :: Software Development :: Version Control',
                 'Programming Language :: Objective C',
                 'Programming Language :: Python :: 2',
                 'Programming Language :: Python :: 2.7'
    ],
)
