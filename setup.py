#    Copyright (C) 2014  Yubico AB
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup
from release import release
import re

VERSION_PATTERN = re.compile(r"(?m)^__version__\s*=\s*['\"](.+)['\"]$")


def get_version():
    """Return the current version as defined by u2flib_server/__init__.py."""

    with open('u2flib_server/__init__.py', 'r') as f:
        match = VERSION_PATTERN.search(f.read())
        return match.group(1)


setup(
    name='python-u2flib-server',
    version=get_version(),
    author='Dain Nilsson',
    author_email='dain@yubico.com',
    description='Python based U2F server library',
    maintainer='Yubico Open Source Maintainers',
    maintainer_email='ossmaint@yubico.com',
    url='https://github.com/Yubico/python-u2flib-server',
    packages=['u2flib_server', 'u2flib_server.attestation'],
    setup_requires=['nose>=1.0'],
    install_requires=['M2Crypto', 'pyasn1', 'pyasn1-modules'],
    test_suite='nose.collector',
    tests_require=[''],
    cmdclass={'release': release},
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
