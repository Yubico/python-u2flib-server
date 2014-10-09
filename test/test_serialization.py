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

from u2flib_server import u2f_v2 as u2f
from u2flib_server.jsapi import RegisterRequest


def test_enroll_serialization():
    enroll1 = u2f.start_register('https://example.com')
    enroll2 = RegisterRequest(enroll1.json)

    assert enroll1.appId == enroll2.appId
    assert enroll1.json == enroll2.json
