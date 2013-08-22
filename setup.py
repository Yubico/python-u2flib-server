# Copyright (C) 2013 Yubico AB.
# All rights reserved.
# Proprietary code owned by Yubico AB.
# No rights to modifications or redistribution.

from setuptools import setup
from release import release

setup(
    name='python-u2flib-server',
    version='0.0.1',
    author='Dain Nilsson',
    author_email='dain@yubico.com',
    maintainer='Yubico Open Source Maintainers',
    maintainer_email='ossmaint@yubico.com',
    url='https://github.com/Yubico/python-u2flib-server',
    license='proprietary',
    packages=['u2flib_server'],
    setup_requires=['nose>=1.0'],
    install_requires=['M2Crypto'],
    test_suite='nose.collector',
    tests_require=[''],
    cmdclass={'release': release},
    classifiers=[
        'License :: Other/Proprietary License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
