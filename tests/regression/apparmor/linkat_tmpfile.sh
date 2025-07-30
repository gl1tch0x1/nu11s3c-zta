#! /bin/bash
#	Copyright (C) 2025 Canonical, Ltd.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License as
#	published by the Free Software Foundation, version 2 of the
#	License.

#=NAME linkat
#=DESCRIPTION
# Verifies that file creation with O_TMPFILE and linkat(2) is mediated correctly
#=END

pwd=`dirname $0`
pwd=`cd $pwd ; /bin/pwd`

bin=$pwd

. "$bin/prologue.inc"

tmpdir_nested=$tmpdir/nested
tmpdir_nested_file=$tmpdir_nested/file
tmpfile=$tmpdir/file

mkdir $tmpdir_nested

genprofile cap:dac_read_search
runchecktest "linkat O_TMPFILE noperms" fail $tmpdir_nested
runchecktest "linkat O_TMPFILE noperms, link" fail $tmpdir_nested $tmpfile

# Denial log entry for tmpfile is /path/#[6digits]
# Don't assume because O_TMPFILE fds should lack a name entirely
genprofile cap:dac_read_search "${tmpdir_nested}/:w" "${tmpdir_nested}/*:w"
runchecktest "linkat O_TMPFILE tmpdir only" pass $tmpdir_nested
runchecktest "linkat O_TMPFILE tmpdir only, link" fail $tmpdir_nested $tmpfile

genprofile cap:dac_read_search "${tmpfile}:w"
runchecktest "linkat O_TMPFILE tmpfile only" fail $tmpdir_nested
runchecktest "linkat O_TMPFILE tmpfile only, link" fail $tmpdir_nested $tmpfile

genprofile cap:dac_read_search "${tmpdir_nested}/:w" "${tmpdir_nested}/*:w" "${tmpfile}:w"
runchecktest "linkat O_TMPFILE tmpdir and tmpfile (w)" pass $tmpdir_nested
# Even if semantically a (w)rite it gets logged as the (l)ink that it actually is
runchecktest "linkat O_TMPFILE tmpdir and tmpfile (w), link" xpass $tmpdir_nested $tmpfile

genprofile cap:dac_read_search "${tmpdir_nested}/:w" "${tmpdir_nested}/*:w" "${tmpfile}:l"
runchecktest "linkat O_TMPFILE tmpdir and tmpfile (l)" pass $tmpdir_nested
# Even if semantically a (w)rite we want to test backwards compatibility with (l)ink as it is currently seen
runchecktest "linkat O_TMPFILE tmpdir and tmpfile (l), link" pass $tmpdir_nested $tmpfile

rm $tmpfile
rmdir $tmpdir_nested