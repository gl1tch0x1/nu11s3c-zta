/*
 *   Copyright (c) 2025
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
 *   along with this program; if not, contact Canonical Ltd.
 */

#ifndef __AA_VARIABLE_H
#define __AA_VARIABLE_H

#include <set>
#include <string>
#include "parser.h"

enum var_type {
	sd_boolean,
	sd_set,
};

class variable {
public:
	enum var_type type;
	std::string var_name;
	int boolean;
	std::set<std::string> values;
	std::set<std::string> expanded;
	std::string expanding_by = "";
	bool expanding = false;

	variable(const char *var_name, struct value_list *values);
	variable(const char *var_name, const char *value);
	variable(const char *var_name, int boolean);

	int add_set_value(struct value_list *value);
	int expand_variable(void);
	static int expand_by_alternation(char **name);
	void dump_set_values(std::set<std::string> values);
	void dump(bool expanded);

	virtual ~variable() {};

	/* strip off surrounding delimiters around variables */
	static char *process_var(const char *var);
};

std::tuple<std::string, std::string, std::string> extract_variable(const std::string& input);

#endif /* __AA_VARIABLE_H */
