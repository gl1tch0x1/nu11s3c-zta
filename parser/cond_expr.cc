/*
 *   Copyright (c) 2024
 *   Canonical Ltd. (All rights reserved)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, contact Novell, Inc. or Canonical
 *   Ltd.
 */

#include "cond_expr.h"
#include "parser.h"
#include "symtab.h"

cond_expr::cond_expr(bool result):
	result(result)
{
}

cond_expr::cond_expr(const char *var, bool defined)
{
	variable *ref;
	if (!defined) {
		ref = symtab::get_boolean_var(var);
		if (!ref) {
			/* FIXME check for set var */
			yyerror(_("Unset boolean variable %s used in if-expression"), var);
		}
		result = ref->boolean;
	} else {
		ref = symtab::get_set_var(var);
		if (!ref) {
			result = false;
		} else {
			PDEBUG("Matched: defined set expr %s value %s\n", var, ref->expanded.begin()->c_str());
			result = true;
		}
	}
}
