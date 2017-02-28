# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import


from setuptools import setup as _setup, find_packages, Command
from setuptools.command.sdist import sdist
from distutils import log
from distutils.errors import DistutilsSetupError
from datetime import date
from glob import glob
import os
import re

VERSION_PATTERN = re.compile(r"(?m)^__version__\s*=\s*['\"](.+)['\"]$")

base_module = __name__.rsplit('.', 1)[0]


def get_version(module_name_or_file=None):
    """Return the current version as defined by the given module/file."""

    if module_name_or_file is None:
        parts = base_module.split('.')
        module_name_or_file = parts[0] if len(parts) > 1 else \
            find_packages(exclude=['test', 'test.*'])[0]

    if os.path.isdir(module_name_or_file):
        module_name_or_file = os.path.join(module_name_or_file, '__init__.py')

    with open(module_name_or_file, 'r') as f:
        match = VERSION_PATTERN.search(f.read())
        return match.group(1)


def setup(**kwargs):
    if 'version' not in kwargs:
        kwargs['version'] = get_version()
    kwargs.setdefault('packages', find_packages(exclude=['test', 'test.*']))
    cmdclass = kwargs.setdefault('cmdclass', {})
    cmdclass.setdefault('release', release)
    cmdclass.setdefault('build_man', build_man)
    cmdclass.setdefault('sdist', custom_sdist)
    return _setup(**kwargs)


class custom_sdist(sdist):
    def run(self):
        self.run_command('build_man')

        sdist.run(self)


class build_man(Command):
    description = "create man pages from asciidoc source"
    user_options = []
    boolean_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        self.cwd = os.getcwd()
        self.fullname = self.distribution.get_fullname()
        self.name = self.distribution.get_name()
        self.version = self.distribution.get_version()

    def run(self):
        if os.getcwd() != self.cwd:
            raise DistutilsSetupError("Must be in package root!")

        for fname in glob(os.path.join('man', '*.adoc')):
            self.announce("Converting: " + fname, log.INFO)
            self.execute(os.system,
                         ('a2x -d manpage -f manpage "%s"' % fname,))


class release(Command):
    description = "create and release a new version"
    user_options = [
        ('keyid', None, "GPG key to sign with"),
        ('skip-tests', None, "skip running the tests"),
        ('pypi', None, "publish to pypi"),
    ]
    boolean_options = ['skip-tests', 'pypi']

    def initialize_options(self):
        self.keyid = None
        self.skip_tests = 0
        self.pypi = 0

    def finalize_options(self):
        self.cwd = os.getcwd()
        self.fullname = self.distribution.get_fullname()
        self.name = self.distribution.get_name()
        self.version = self.distribution.get_version()

    def _verify_version(self):
        with open('NEWS', 'r') as news_file:
            line = news_file.readline()
        now = date.today().strftime('%Y-%m-%d')
        if not re.search(r'Version %s \(released %s\)' % (self.version, now),
                         line):
            raise DistutilsSetupError("Incorrect date/version in NEWS!")

    def _verify_tag(self):
        if os.system('git tag | grep -q "^%s\$"' % self.fullname) == 0:
            raise DistutilsSetupError(
                "Tag '%s' already exists!" % self.fullname)

    def _verify_not_dirty(self):
        if os.system('git diff --shortstat | grep -q "."') == 0:
            raise DistutilsSetupError("Git has uncommitted changes!")

    def _sign(self):
        if os.path.isfile('dist/%s.tar.gz.asc' % self.fullname):
            # Signature exists from upload, re-use it:
            sign_opts = ['--output dist/%s.tar.gz.sig' % self.fullname,
                         '--dearmor dist/%s.tar.gz.asc' % self.fullname]
        else:
            # No signature, create it:
            sign_opts = ['--detach-sign', 'dist/%s.tar.gz' % self.fullname]
            if self.keyid:
                sign_opts.insert(1, '--default-key ' + self.keyid)
        self.execute(os.system, ('gpg ' + (' '.join(sign_opts)),))

        if os.system('gpg --verify dist/%s.tar.gz.sig' % self.fullname) != 0:
            raise DistutilsSetupError("Error verifying signature!")

    def _tag(self):
        tag_opts = ['-s', '-m ' + self.fullname, self.fullname]
        if self.keyid:
            tag_opts[0] = '-u ' + self.keyid
        self.execute(os.system, ('git tag ' + (' '.join(tag_opts)),))

    def run(self):
        if os.getcwd() != self.cwd:
            raise DistutilsSetupError("Must be in package root!")

        self._verify_version()
        self._verify_tag()
        self._verify_not_dirty()
        self.run_command('check')

        self.execute(os.system, ('git2cl > ChangeLog',))

        self.run_command('sdist')

        if not self.skip_tests:
            try:
                self.run_command('test')
            except SystemExit as e:
                if e.code != 0:
                    raise DistutilsSetupError("There were test failures!")

        if self.pypi:
            cmd_obj = self.distribution.get_command_obj('upload')
            cmd_obj.sign = True
            if self.keyid:
                cmd_obj.identity = self.keyid
            self.run_command('upload')

        self._sign()
        self._tag()

        self.announce("Release complete! Don't forget to:", log.INFO)
        self.announce("")
        self.announce("    git push && git push --tags", log.INFO)
        self.announce("")
