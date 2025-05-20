#!/usr/bin/python3
# ----------------------------------------------------------------------
#    Copyright (C) 2020 Christian Boltz <apparmor@cboltz.de>
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of version 2 of the GNU General Public
#    License as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
# ----------------------------------------------------------------------

import os
import shutil
import unittest
from collections import namedtuple

from apparmor.common import AppArmorBug, AppArmorException
from apparmor.rule.include import IncludeRule, IncludeRuleset
from apparmor.translations import init_translation
from common_test import AATest, setup_all_loops, write_file

_ = init_translation()

exp = namedtuple(
    'exp', (  # 'audit', 'allow_keyword', 'deny',
        'comment', 'path', 'ifexists', 'ismagic'))

# --- tests for single IncludeRule --- #


class IncludeTest(AATest):
    def _compare_obj(self, obj, expected):
        self.assertEqual(False, obj.allow_keyword)  # not supported in include rules, expected to be always False
        self.assertEqual(False, obj.audit)          # not supported in include rules, expected to be always False
        self.assertEqual(False, obj.deny)           # not supported in include rules, expected to be always False
        self.assertEqual(None, obj.priority)        # not supported in include rules, expected to be always None
        self.assertEqual(expected.comment, obj.comment)

        self.assertEqual(expected.path, obj.path)
        self.assertEqual(expected.ifexists, obj.ifexists)
        self.assertEqual(expected.ismagic, obj.ismagic)


class IncludeTestParse(IncludeTest):
    tests = (
        # IncludeRule object                                      comment       path                 if exists  ismagic
        # #include
        ('#include <abstractions/base>',                      exp('',           'abstractions/base', False,     True)),  # magic path
        ('#include <abstractions/base> # comment',            exp(' # comment', 'abstractions/base', False,     True)),
        ('#include<abstractions/base>#comment',               exp(' #comment',  'abstractions/base', False,     True)),
        ('   #include     <abstractions/base>  ',             exp('',           'abstractions/base', False,     True)),
        ('#include "/foo/bar"',                               exp('',           '/foo/bar',          False,     False)),  # absolute path
        ('#include "/foo/bar" # comment',                     exp(' # comment', '/foo/bar',          False,     False)),
        ('#include "/foo/bar"#comment',                       exp(' #comment',  '/foo/bar',          False,     False)),
        ('   #include "/foo/bar"  ',                          exp('',           '/foo/bar',          False,     False)),
        # include (without #)
        ('include <abstractions/base>',                       exp('',           'abstractions/base', False,     True)),  # magic path
        ('include <abstractions/base> # comment',             exp(' # comment', 'abstractions/base', False,     True)),
        ('include<abstractions/base>#comment',                exp(' #comment',  'abstractions/base', False,     True)),
        ('   include     <abstractions/base>  ',              exp('',           'abstractions/base', False,     True)),
        ('include "/foo/bar"',                                exp('',           '/foo/bar',          False,     False)),  # absolute path
        ('include "/foo/bar" # comment',                      exp(' # comment', '/foo/bar',          False,     False)),
        ('include "/foo/bar"#comment',                        exp(' #comment',  '/foo/bar',          False,     False)),
        ('   include "/foo/bar"  ',                           exp('',           '/foo/bar',          False,     False)),
        # #include if exists
        ('#include if exists <abstractions/base>',            exp('',           'abstractions/base', True,      True)),  # magic path
        ('#include if exists <abstractions/base> # comment',  exp(' # comment', 'abstractions/base', True,      True)),
        ('#include if exists<abstractions/base>#comment',     exp(' #comment',  'abstractions/base', True,      True)),
        ('   #include    if     exists<abstractions/base>  ', exp('',           'abstractions/base', True,      True)),
        ('#include if exists "/foo/bar"',                     exp('',           '/foo/bar',          True,      False)),  # absolute path
        ('#include if exists "/foo/bar" # comment',           exp(' # comment', '/foo/bar',          True,      False)),
        ('#include if exists "/foo/bar"#comment',             exp(' #comment',  '/foo/bar',          True,      False)),
        ('   #include if exists "/foo/bar"  ',                exp('',           '/foo/bar',          True,      False)),
        # include if exists (without #)
        ('include if exists <abstractions/base>',             exp('',           'abstractions/base', True,      True)),  # magic path
        ('include if exists <abstractions/base> # comment',   exp(' # comment', 'abstractions/base', True,      True)),
        ('include if exists<abstractions/base>#comment',      exp(' #comment',  'abstractions/base', True,      True)),
        ('   include    if     exists<abstractions/base>  ',  exp('',           'abstractions/base', True,      True)),
        ('include if exists "/foo/bar"',                      exp('',           '/foo/bar',          True,      False)),  # absolute path
        ('include if exists "/foo/bar" # comment',            exp(' # comment', '/foo/bar',          True,      False)),
        ('include if exists "/foo/bar"#comment',              exp(' #comment',  '/foo/bar',          True,      False)),
        ('   include if exists "/foo/bar"  ',                 exp('',           '/foo/bar',          True,      False)),
    )

    def _run_test(self, rawrule, expected):
        self.assertTrue(IncludeRule.match(rawrule))
        obj = IncludeRule.create_instance(rawrule)
        self.assertEqual(rawrule.strip(), obj.raw_rule)
        self._compare_obj(obj, expected)


class IncludeTestParseInvalid(IncludeTest):
    tests = (
        # (' some #include if exists <abstractions/base>', AppArmorException),
        # ('  /etc/fstab r,',                              AppArmorException),
        # ('/usr/include r,',                              AppArmorException),
        # ('/include r,',                                  AppArmorException),
    )

    def _run_test(self, rawrule, expected):
        self.assertTrue(IncludeRule.match(rawrule))  # the above invalid rules still match the main regex!
        with self.assertRaises(expected):
            IncludeRule.create_instance(rawrule)

# class IncludeTestParseFromLog(IncludeTest):  # we'll never have log events for includes


class IncludeFromInit(IncludeTest):
    tests = (
        # IncludeRule object            ifexists  ismagic                     comment  path               ifexists  ismagic
        (IncludeRule('abstractions/base', False, False),                  exp('',      'abstractions/base', False, False)),
        (IncludeRule('foo',               True,  False),                  exp('',      'foo',               True,  False)),
        (IncludeRule('bar',               False, True),                   exp('',      'bar',               False, True)),
        (IncludeRule('baz',               True,  True),                   exp('',      'baz',               True,  True)),
        (IncludeRule('comment',           False, False, comment='# cmt'), exp('# cmt', 'comment',           False, False)),
    )

    def _run_test(self, obj, expected):
        self._compare_obj(obj, expected)


class InvalidIncludeInit(AATest):
    tests = (
        # init params            expected exception
        ((False,  False, False), AppArmorBug),  # wrong type for path
        (('',     False, False), AppArmorBug),  # empty path
        ((None,   False, False), AppArmorBug),  # wrong type for path
        # (('    ', False, False), AppArmorBug),  # whitespace-only path
        (('foo',  None,  False), AppArmorBug),  # wrong type for ifexists
        (('foo',  '',    False), AppArmorBug),  # wrong type for ifexists
        (('foo',  False, None),  AppArmorBug),  # wrong type for ismagic
        (('foo',  False, ''),    AppArmorBug),  # wrong type for ismagic
    )

    def _run_test(self, params, expected):
        with self.assertRaises(expected):
            IncludeRule(*params)

    def test_missing_params_1(self):
        with self.assertRaises(TypeError):
            IncludeRule()

    def test_missing_params_2(self):
        with self.assertRaises(TypeError):
            IncludeRule('foo')

    def test_missing_params_3(self):
        with self.assertRaises(TypeError):
            IncludeRule('foo', False)

    def test_audit_true(self):
        with self.assertRaises(AppArmorBug):
            IncludeRule('foo', False, False, audit=True)

    def test_deny_true(self):
        with self.assertRaises(AppArmorBug):
            IncludeRule('foo', False, False, deny=True)

    def test_priority_true(self):
        with self.assertRaises(AppArmorBug):
            IncludeRule('foo', False, False, priority=0)


class InvalidIncludeTest(AATest):
    def _check_invalid_rawrule(self, rawrule, matches_regex=False):
        obj = None
        self.assertEqual(IncludeRule.match(rawrule), matches_regex)
        with self.assertRaises(AppArmorException):
            obj = IncludeRule.create_instance(rawrule)

        self.assertIsNone(obj, 'IncludeRule handed back an object unexpectedly')

    def test_invalid_include_missing_path(self):
        self._check_invalid_rawrule('include', matches_regex=True)  # missing path

    def test_invalid_non_IncludeRule(self):
        self._check_invalid_rawrule('dbus,')  # not a include rule

    # def test_empty_data_1(self):
    #     obj = IncludeRule('foo', False, False)
    #     obj.path = ''
    #     # no path set
    #     with self.assertRaises(AppArmorBug):
    #         obj.get_clean(1)


class WriteIncludeTestAATest(AATest):
    def _run_test(self, rawrule, expected):
        self.assertTrue(IncludeRule.match(rawrule))
        obj = IncludeRule.create_instance(rawrule)
        clean = obj.get_clean()
        raw = obj.get_raw()

        self.assertEqual(expected.strip(), clean, 'unexpected clean rule')
        self.assertEqual(rawrule.strip(), raw, 'unexpected raw rule')

    tests = (
        #  (raw rule, clean rule)
        ('     include      <foo>            ',             'include <foo>'),
        # ('     include       foo             ',             'include "foo"'),  # several test cases disabled due to implementation restrictions, see re_match_include_parse()
        # ('     include      "foo"            ',             'include "foo"'),
        # ('     include       /foo             ',            'include "/foo"'),
        ('     include      "/foo"            ',            'include "/foo"'),

        ('     include      <foo>  # bar     ',             'include <foo> # bar'),
        # ('     include       foo   # bar     ',             'include "foo" # bar'),
        # ('     include      "foo"  # bar     ',             'include "foo" # bar'),
        # ('     include       /foo   # bar     ',            'include "/foo" # bar'),
        ('     include      "/foo"  # bar     ',            'include "/foo" # bar'),

        ('     include if    exists     <foo>            ', 'include if exists <foo>'),
        # ('     include if    exists      foo             ', 'include if exists "foo"'),
        # ('     include if    exists     "foo"            ', 'include if exists "foo"'),
        # ('     include if    exists      /foo            ', 'include if exists "/foo"'),
        ('     include if    exists     "/foo"           ', 'include if exists "/foo"'),

        # and the same again with #include...
        ('    #include      <foo>            ',             'include <foo>'),
        # ('    #include       foo             ',             'include "foo"'),
        # ('    #include      "foo"            ',             'include "foo"'),
        # ('    #include       /foo             ',            'include "/foo"'),
        ('    #include      "/foo"            ',            'include "/foo"'),

        ('    #include      <foo>  # bar     ',             'include <foo> # bar'),
        # ('    #include       foo   # bar     ',             'include "foo" # bar'),
        # ('    #include      "foo"  # bar     ',             'include "foo" # bar'),
        # ('    #include       /foo   # bar     ',            'include "/foo" # bar'),
        ('    #include      "/foo"  # bar     ',            'include "/foo" # bar'),

        ('    #include if    exists     <foo>            ', 'include if exists <foo>'),
        # ('    #include if    exists      foo             ', 'include if exists "foo"'),
        # ('    #include if    exists     "foo"            ', 'include if exists "foo"'),
        # ('    #include if    exists      /foo            ', 'include if exists "/foo"'),
        ('    #include if    exists     "/foo"           ', 'include if exists "/foo"'),
    )

    def test_write_manually(self):
        obj = IncludeRule('abs/foo', False, True, comment=' # cmt')

        expected = '    include <abs/foo> # cmt'

        self.assertEqual(expected, obj.get_clean(2), 'unexpected clean rule')
        self.assertEqual(expected, obj.get_raw(2), 'unexpected raw rule')


class IncludeCoveredTest(AATest):
    def _run_test(self, param, expected):
        obj = IncludeRule.create_instance(self.rule)
        check_obj = IncludeRule.create_instance(param)

        self.assertTrue(IncludeRule.match(param))

        self.assertEqual(obj.is_equal(check_obj), expected[0], 'Mismatch in is_equal, expected {}'.format(expected[0]))
        self.assertEqual(obj.is_equal(check_obj, True), expected[1], 'Mismatch in is_equal/strict, expected {}'.format(expected[1]))

        self.assertEqual(obj.is_covered(check_obj), expected[2], 'Mismatch in is_covered, expected {}'.format(expected[2]))
        self.assertEqual(obj.is_covered(check_obj, True, True), expected[3], 'Mismatch in is_covered/exact, expected {}'.format(expected[3]))


class IncludeCoveredTest_01(IncludeCoveredTest):
    rule = 'include <foo>'

    tests = (
        #   rule                      equal  strict equal  covered  covered exact
        ('include <foo>',            (True,  True,         True,    True)),
        ('#include <foo>',           (True,  False,        True,    True)),
        ('include if exists <foo>',  (False, False,        True,    True)),
        ('#include if exists <foo>', (False, False,        True,    True)),
        ('include <foobar>',         (False, False,        False,   False)),
        # ('include "foo"',            (False, False,        False,   False)),  # disabled due to implementation restrictions, see re_match_include_parse()
        # ('include if exists "foo"',  (False, False,        False,   False)),
    )


class IncludeCoveredTest_02(IncludeCoveredTest):
    rule = 'include if exists <foo>'

    tests = (
        #   rule                      equal  strict equal  covered  covered exact
        ('include <foo>',            (False, False,        False,   False)),
        ('#include <foo>',           (False, False,        False,   False)),
        ('#include if exists <foo>', (True,  False,        True,    True)),
        ('include <foobar>',         (False, False,        False,   False)),
        # ('include "foo"',            (False, False,        False,   False)),  # disabled due to implementation restrictions, see re_match_include_parse()
        # ('include if exists "foo"',  (False, False,        False,   False)),
    )


class IncludeCoveredTest_Invalid(AATest):
    # def test_borked_obj_is_covered_1(self):
    #     obj = IncludeRule.create_instance('include <foo>')
    #
    #     testobj = IncludeRule('foo', True, True)
    #     testobj.path = ''
    #
    #     with self.assertRaises(AppArmorBug):
    #         obj.is_covered(testobj)

    def test_invalid_is_covered(self):
        raw_rule = 'include <abstractions/base>'

        class SomeOtherClass(IncludeRule):
            pass

        obj = IncludeRule.create_instance(raw_rule)
        testobj = SomeOtherClass.create_instance(raw_rule)  # different type
        with self.assertRaises(AppArmorBug):
            obj.is_covered(testobj)

    def test_invalid_is_equal(self):
        raw_rule = 'include <abstractions/base>'

        class SomeOtherClass(IncludeRule):
            pass

        obj = IncludeRule.create_instance(raw_rule)
        testobj = SomeOtherClass.create_instance(raw_rule)  # different type
        with self.assertRaises(AppArmorBug):
            obj.is_equal(testobj)


class IncludeLogprofHeaderTest(AATest):
    tests = (
        ('include <abstractions/base>', [_('Include'), 'include <abstractions/base>']),
        ('include "/what/ever"',        [_('Include'), 'include "/what/ever"']),
    )

    def _run_test(self, params, expected):
        obj = IncludeRule.create_instance(params)
        self.assertEqual(obj.logprof_header(), expected)


class IncludeFullPathsTest(AATest):
    def AASetup(self):
        self.createTmpdir()

        # copy the local profiles to the test directory
        self.profile_dir = self.tmpdir + '/profiles'
        shutil.copytree('../../profiles/apparmor.d/', self.profile_dir, symlinks=True)

        inc_dir = os.path.join(self.profile_dir, 'abstractions/inc.d')
        os.mkdir(inc_dir, 0o755)
        write_file(inc_dir, 'incfoo', '/incfoo r,')
        write_file(inc_dir, 'incbar', '/incbar r,')
        write_file(inc_dir, 'README', '# README')  # gets skipped

        sub_dir = os.path.join(self.profile_dir, 'abstractions/inc.d/subdir')  # gets skipped
        os.mkdir(sub_dir, 0o755)

        empty_dir = os.path.join(self.profile_dir, 'abstractions/empty.d')
        os.mkdir(empty_dir, 0o755)

    tests = (
        #                                                @@ will be replaced with self.profile_dir
        ('include <abstractions/base>',                ('@@/abstractions/base',)),
        # ('include "foo"',                              ('@@/foo',)),  # TODO: adjust logic to honor quoted vs. magic paths (and allow quoted relative paths in re_match_include_parse())
        ('include "/foo/bar"',                         ('/foo/bar',)),
        ('include <abstractions/inc.d>',               ('@@/abstractions/inc.d/incbar', '@@/abstractions/inc.d/incfoo')),
        ('include <abstractions/empty.d>',             ()),
        ('include <abstractions/not_found>',           ('@@/abstractions/not_found',)),
        ('include if exists <abstractions/not_found>', ()),
    )

    def _run_test(self, params, expected):
        exp2 = []
        for path in expected:
            exp2.append(path.replace('@@', self.profile_dir))

        obj = IncludeRule.create_instance(params)
        self.assertEqual(obj.get_full_paths(self.profile_dir), exp2)


# --- tests for IncludeRuleset --- #

class IncludeRulesTest(AATest):
    def AASetup(self):
        self.createTmpdir()

        # copy the local profiles to the test directory
        self.profile_dir = self.tmpdir + '/profiles'
        shutil.copytree('../../profiles/apparmor.d/', self.profile_dir, symlinks=True)

        write_file(self.profile_dir, 'baz', '/baz r,')

    def test_empty_ruleset(self):
        ruleset = IncludeRuleset()
        ruleset_2 = IncludeRuleset()
        self.assertEqual([], ruleset.get_raw(2))
        self.assertEqual([], ruleset.get_clean(2))
        self.assertEqual([], ruleset_2.get_raw(2))
        self.assertEqual([], ruleset_2.get_clean(2))
        self.assertEqual([], ruleset_2.get_clean_unsorted(2))
        self.assertEqual([], ruleset.get_all_full_paths(self.profile_dir))

    def test_ruleset_1(self):
        ruleset = IncludeRuleset()
        rules = (
            ' include  <foo>  ',
            ' #include   "/bar" ',
        )

        expected_raw = [
            'include  <foo>',
            '#include   "/bar"',
            '',
        ]

        expected_clean = [
            'include "/bar"',
            'include <foo>',
            '',
        ]

        expected_clean_unsorted = [
            'include <foo>',
            'include "/bar"',
            '',
        ]

        expected_fullpaths = [
            os.path.join(self.profile_dir, 'foo'),
            '/bar'
        ]

        for rule in rules:
            ruleset.add(IncludeRule.create_instance(rule))

        self.assertEqual(expected_raw, ruleset.get_raw())
        self.assertEqual(expected_clean, ruleset.get_clean())
        self.assertEqual(expected_clean_unsorted, ruleset.get_clean_unsorted())
        self.assertEqual(expected_fullpaths, ruleset.get_all_full_paths(self.profile_dir))

    def test_ruleset_2(self):
        ruleset = IncludeRuleset()
        rules = (
            '   include   if  exists  <baz> ',
            ' include  <foo>  ',
            ' #include   "/bar" ',
            '#include if   exists   "/asdf"  ',
        )

        expected_raw = [
            'include   if  exists  <baz>',
            'include  <foo>',
            '#include   "/bar"',
            '#include if   exists   "/asdf"',
            '',
        ]

        expected_clean = [
            'include "/bar"',
            'include <foo>',
            'include if exists "/asdf"',
            'include if exists <baz>',
            '',
        ]

        expected_clean_unsorted = [
            'include if exists <baz>',
            'include <foo>',
            'include "/bar"',
            'include if exists "/asdf"',
            '',
        ]

        expected_fullpaths = [
            os.path.join(self.profile_dir, 'baz'),
            os.path.join(self.profile_dir, 'foo'),
            '/bar',
        ]

        for rule in rules:
            ruleset.add(IncludeRule.create_instance(rule))

        self.assertEqual(expected_raw, ruleset.get_raw())
        self.assertEqual(expected_clean, ruleset.get_clean())
        self.assertEqual(expected_clean_unsorted, ruleset.get_clean_unsorted())
        self.assertEqual(expected_fullpaths, ruleset.get_all_full_paths(self.profile_dir))


class IncludeGlobTestAATest(AATest):
    def setUp(self):
        self.maxDiff = None
        self.ruleset = IncludeRuleset()

    # def test_glob(self):
    #     with self.assertRaises(NotImplementedError):
    #         # get_glob_ext is not available for include rules
    #         self.ruleset.get_glob('include send set=int,')

    def test_glob_ext(self):
        with self.assertRaises(NotImplementedError):
            # get_glob_ext is not available for include rules
            self.ruleset.get_glob_ext('include send set=int,')


# class IncludeDeleteTestAATest(AATest):
#     pass


setup_all_loops(__name__)
if __name__ == '__main__':
    unittest.main(verbosity=1)
