#! /usr/bin/python3
# ------------------------------------------------------------------
#
#    Copyright (C) 2011-2012 Canonical Ltd.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License published by the Free Software Foundation.
#
# ------------------------------------------------------------------

import os
import unittest
from tempfile import NamedTemporaryFile
from apparmor.common import cmd_pipe_stderr
# The location of the aa-decode utility can be overridden by setting
# the APPARMOR_DECODE environment variable; this is useful for running
# these tests in an installed environment
aadecode_bin = "../aa-decode"


class AADecodeTest(unittest.TestCase):

    def test_help(self):
        """Test --help argument"""

        expected = 0
        rc, report = cmd_pipe_stderr((aadecode_bin, "--help"))
        result = 'Got exit code {}, expected {}\n'.format(rc, expected)
        self.assertEqual(expected, rc, result + report)

    def _run_file_test(self, content, expected):
        """test case helper function; takes log content and a list of
           expected strings as arguments"""

        expected_return_code = 0

        with NamedTemporaryFile("w+", prefix='tst-aadecode-') as temp_file:
            self.tmpfile = temp_file.name
            temp_file.write(content)
            temp_file.flush()
            temp_file.seek(0)
            rc, report = cmd_pipe_stderr(aadecode_bin, stdin=temp_file)

        result = 'Got exit code {}, expected {}\n'.format(rc, expected_return_code)
        self.assertEqual(expected_return_code, rc, result + report)
        for expected_string in expected:
            result = 'could not find expected {} in output:\n'.format(expected_string)
            self.assertIn(expected_string, report, result + report)

    def test_simple_decode(self):
        """Test simple decode on command line"""

        expected = 0
        expected_output = 'Decoded: /tmp/foo bar'
        test_code = '2F746D702F666F6F20626172'

        rc, report = cmd_pipe_stderr((aadecode_bin, test_code))
        result = 'Got exit code {}, expected {}\n'.format(rc, expected)
        self.assertEqual(expected, rc, result + report)
        result = 'Got output "{}", expected "{}"\n'.format(report, expected_output)
        self.assertIn(expected_output, report, result + report)

    def test_simple_filter(self):
        """test simple decoding of the name argument"""

        expected_string = 'name="/tmp/foo bar"'
        content = \
'''type=AVC msg=audit(1348982151.183:2934): apparmor="DENIED" operation="open" parent=30751 profile="/usr/lib/firefox/firefox{,*[^s] [^h]}" name=2F746D702F666F6F20626172 pid=30833 comm="plugin-containe" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
'''  # noqa: E128

        self._run_file_test(content, (expected_string,))

    def test_simple_multiline(self):
        """test simple multiline decoding of the name argument"""

        expected_strings = (
            'ses=4294967295 new ses=2762',
            'name="/tmp/foo bar"',
            'name="/home/steve/tmp/my test file"',
        )
        content = \
''' type=LOGIN msg=audit(1348980001.155:2925): login pid=17875 uid=0 old auid=4294967295 new auid=0 old ses=4294967295 new ses=2762
type=AVC msg=audit(1348982151.183:2934): apparmor="DENIED" operation="open" parent=30751 profile="/usr/lib/firefox/firefox{,*[^s] [^h]}" name=2F746D702F666F6F20626172 pid=30833 comm="plugin-containe" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
type=AVC msg=audit(1348982148.195:2933): apparmor="DENIED" operation="file_lock" parent=5490 profile="/usr/lib/firefox/firefox{,*[^s][^h]}" name=2F686F6D652F73746576652F746D702F6D7920746573742066696C65 pid=30737 comm="firefox" requested_mask="k" denied_mask="k" fsuid=1000 ouid=1000
'''  # noqa: E128

        self._run_file_test(content, expected_strings)

    def test_simple_profile(self):
        """test simple decoding of the profile argument"""

        # Example take from LP: #897957
        expected_strings = (
            'name="/lib/x86_64-linux-gnu/libdl-2.13.so"', 'profile="/test space"')
        content = \
'''[289763.843292] type=1400 audit(1322614912.304:857): apparmor="ALLOWED" operation="getattr" parent=16001 profile=2F74657374207370616365 name="/lib/x86_64-linux-gnu/libdl-2.13.so" pid=17011 comm="bash" requested_mask="r" denied_mask="r" fsuid=0 ouid=0
'''  # noqa: E128

        self._run_file_test(content, expected_strings)

    def test_simple_profile2(self):
        """test simple decoding of name and profile argument"""

        # Example take from LP: #897957
        expected_strings = ('name="/home/steve/tmp/my test file"',
                            'profile="/home/steve/tmp/my prog.sh"')
        content = \
'''type=AVC msg=audit(1349805073.402:6857): apparmor="DENIED" operation="mknod" parent=5890 profile=2F686F6D652F73746576652F746D702F6D792070726F672E7368 name=2F686F6D652F73746576652F746D702F6D7920746573742066696C65 pid=5891 comm="touch" requested_mask="c" denied_mask="c" fsuid=1000 ouid=1000
'''  # noqa: E128

        self._run_file_test(content, expected_strings)

    def test_simple_embedded_carat(self):
        """test simple decoding of embedded ^ in files"""

        expected_strings = ('name="/home/steve/tmp/my test ^file"',)
        content = \
'''type=AVC msg=audit(1349805073.402:6857): apparmor="DENIED" operation="mknod" parent=5890 profile="/usr/bin/test_profile" name=2F686F6D652F73746576652F746D702F6D792074657374205E66696C65 pid=5891 comm="touch" requested_mask="c" denied_mask="c" fsuid=1000 ouid=1000
'''  # noqa: E128

        self._run_file_test(content, expected_strings)

    def test_simple_embedded_backslash_carat(self):
        r"""test simple decoding of embedded \^ in files"""

        expected_strings = (r'name="/home/steve/tmp/my test \^file"',)
        content = \
'''type=AVC msg=audit(1349805073.402:6857): apparmor="DENIED" operation="mknod" parent=5890 profile="/usr/bin/test_profile" name=2F686F6D652F73746576652F746D702F6D792074657374205C5E66696C65 pid=5891 comm="touch" requested_mask="c" denied_mask="c" fsuid=1000 ouid=1000
'''  # noqa: E128

        self._run_file_test(content, expected_strings)

    def test_simple_embedded_singlequote(self):
        """test simple decoding of embedded \' in files"""

        expected_strings = ('name="/home/steve/tmp/my test \'file"',)
        content = \
'''type=AVC msg=audit(1349805073.402:6857): apparmor="DENIED" operation="mknod" parent=5890 profile="/usr/bin/test_profile" name=2F686F6D652F73746576652F746D702F6D792074657374202766696C65 pid=5891 comm="touch" requested_mask="c" denied_mask="c" fsuid=1000 ouid=1000
'''  # noqa: E128

        self._run_file_test(content, expected_strings)

    def test_simple_encoded_nonpath_profiles(self):
        """test simple decoding of nonpath profiles"""

        expected_strings = ('name="/lib/x86_64-linux-gnu/libdl-2.13.so"', 'profile="test space"')
        content = \
'''[289763.843292] type=1400 audit(1322614912.304:857): apparmor="ALLOWED" operation="getattr" parent=16001 profile=74657374207370616365 name="/lib/x86_64-linux-gnu/libdl-2.13.so" pid=17011 comm="bash" requested_mask="r" denied_mask="r" fsuid=0 ouid=0
'''  # noqa: E128

        self._run_file_test(content, expected_strings)


#
# Main
#
if __name__ == '__main__':
    if 'APPARMOR_DECODE' in os.environ:
        aadecode_bin = os.environ['APPARMOR_DECODE']
    unittest.main(verbosity=1)
