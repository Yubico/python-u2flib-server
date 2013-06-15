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

from distutils import log
from distutils.core import Command
from distutils.errors import DistutilsSetupError
import os
import re
from datetime import date


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

    def _do_call_publish(self, cmd):
        self._published = os.system(cmd) == 0

    def _publish(self):
        web_repo = os.getenv('YUBICO_GITHUB_REPO')
        if web_repo and os.path.isdir(web_repo):
            artifacts = [
                'dist/%s.tar.gz' % self.fullname,
                'dist/%s.tar.gz.sig' % self.fullname
            ]
            cmd = '%s/publish %s %s %s' % (
                web_repo, self.name, self.version, ' '.join(artifacts))

            self.execute(self._do_call_publish, (cmd,))
            if self._published:
                self.announce("Release published! Don't forget to:", log.INFO)
                self.announce("")
                self.announce("    (cd %s && git push)" % web_repo, log.INFO)
                self.announce("")
            else:
                self.warn("There was a problem publishing the release!")
        else:
            self.warn("YUBICO_GITHUB_REPO not set or invalid!")
            self.warn("This release will not be published!")

    def run(self):
        if os.getcwd() != self.cwd:
            raise DistutilsSetupError("Must be in package root!")

        self._verify_version()
        self._verify_tag()

        self.execute(os.system, ('git2cl > ChangeLog',))

        if not self.skip_tests:
            self.run_command('check')
            # Nosetests calls sys.exit(status)
            try:
                self.run_command('nosetests')
            except SystemExit as e:
                if e.code != 0:
                    raise DistutilsSetupError("There were test failures!")

        self.run_command('sdist')

        if self.pypi:
            cmd_obj = self.distribution.get_command_obj('upload')
            cmd_obj.sign = True
            if self.keyid:
                cmd_obj.identity = self.keyid
            self.run_command('upload')

        self._sign()
        self._tag()

        self._publish()

        self.announce("Release complete! Don't forget to:", log.INFO)
        self.announce("")
        self.announce("    git push && git push --tags", log.INFO)
        self.announce("")
