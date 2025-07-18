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

#include <cctype>
#include <list>
#include <tuple>

#include "variable.h"
#include "symtab.h"

variable::variable(const char *var_name, struct value_list *values):
	type(sd_set),
	var_name(var_name),
	boolean(false) /* not used */
{
	struct value_list *entry = NULL;
	if (!values || !values->value) {
		yyerror("Assert: valuelist returned NULL");
	}
	PDEBUG("Matched: set assignment for (%s)\n", var_name);

	list_for_each(values, entry) {
		this->values.insert(entry->value);
	}
}

variable::variable(const char *var_name, const char *value):
	type(sd_set),
	var_name(var_name),
	boolean(false) /* not used */
{
	PDEBUG("Matched: set assignment for (%s)\n", var_name);
	this->values.insert(value);
}

variable::variable(const char *var_name, int boolean):
	type(sd_boolean),
	var_name(var_name),
	boolean(boolean)
{
	PDEBUG("Matched: boolean assignment (%s) to %d\n", var_name, boolean);
}

char *variable::process_var(const char *var)
{
	const char *orig = var;
	const char *valid;
	int len = strlen(var);
	int i;

	if (*orig == '@' || *orig == '$') {
		orig++;
		len--;
	} else {
		PERROR("ASSERT: Found var '%s' without variable prefix\n",
		       var);
		return NULL;
	}

	if (*orig == '{') {
		orig++;
		len--;
		if (orig[len - 1] != '}') {
			PERROR("ASSERT: No matching '}' in variable '%s'\n",
			       var);
			return NULL;
		} else
			len--;
	}

	valid = orig;
	for (i = 0; i < len; i++) {
		/* first character must be alpha */
		if (valid[i] == *orig) {
			if (!isalpha(valid[i])) {
				PERROR("Variable '%s' must start with alphabet letters\n",
				       var);
				return NULL;
			}
		} else if (!(valid[i] == '_' || isalnum(valid[i]))) {
			PERROR("Variable '%s' contains invalid characters\n",
			       var);
			return NULL;
		}
	}

	return strndup(orig, len);
}

int variable::add_set_value(struct value_list *values)
{
	struct value_list *entry = NULL;
	PDEBUG("Matched: additive assignment for (%s)\n", var_name.c_str());

	if (type != sd_set) {
		PERROR("Variable %s is not a set variable\n", var_name.c_str());
		return 2;
	}

	list_for_each(values, entry) {
		this->values.insert(entry->value);
	}
	return 0;
}

std::tuple<std::string, std::string, std::string> extract_variable(const std::string& input)
{
	std::string prefix = "";
	std::string variable = "";
	std::string suffix = "";

	ssize_t start_pattern_pos = -1;
	ssize_t end_pattern_pos = -1;
	size_t var_len;

	bool bEscape = false;
	size_t i;

	for (i = 0; i < input.size(); i++) {
		switch(input[i]) {
		case '\\':
			bEscape = !bEscape;
			break;
		case '@':
			if (bEscape) {
				bEscape = false;
			} else if (input[i + 1] == '{') {
				start_pattern_pos = i;
				i += 2;
			}
			break;
		case '}':
			if (bEscape) {
				bEscape = false;
			} else if (start_pattern_pos != -1) {
				end_pattern_pos = i;
				goto found;
			}
			break;
		default:
			bEscape = false;
			break;
		}
	}

found:
	if (start_pattern_pos == -1 || end_pattern_pos == -1) {
		return std::make_tuple(prefix, variable, suffix); // "@{" or '}' not found
	}

	var_len = end_pattern_pos - start_pattern_pos + 1;

	prefix = input.substr(0, start_pattern_pos);
	variable = input.substr(start_pattern_pos, var_len);
	suffix = input.substr(end_pattern_pos + 1);

	return std::make_tuple(prefix, variable, suffix);
}

static void trim_leading_slash(std::string& str)
{
	std::size_t found = str.find_first_not_of('/');
	if (found != std::string::npos)
		str.erase(0, found);
	else
		str.clear(); // str is all '/'
}

static void trim_trailing_slash(std::string& str)
{
	std::size_t found = str.find_last_not_of('/');
	if (found != std::string::npos)
		str.erase(found + 1);
	else
		str.clear(); // str is all '/'
}

int variable::expand_by_alternation(char **name)
{
	std::string expanded_name = "";
	bool filter_leading_slash = false;
	bool filter_trailing_slash = false;

	if (!name) {
		PERROR("ASSERT: name to be expanded cannot be NULL\n");
		exit(1);
	}
	if (!*name)		/* can happen when entry is optional */
		return 0;

	auto result = extract_variable(*name);
	std::string prefix = std::get<0>(result);
	std::string var = std::get<1>(result);
	std::string suffix = std::get<2>(result);

	if (prefix.empty() && var.empty() && suffix.empty()) {
		return 0; /* no var found, name is unchanged */
	}

	free(*name);

	if (!prefix.empty() && prefix[prefix.size() - 1] == '/') {
		/* make sure to not collapse / in the beginning of the path */
		std::size_t found = prefix.find_first_not_of('/');
		if (found != std::string::npos)
			filter_leading_slash = true;
	}
	if (!suffix.empty() && suffix[0] == '/')
		filter_trailing_slash = true;

	variable *ref = symtab::get_set_var(var.c_str());
	if (!ref) {
		PERROR("Failed to find declaration for: %s\n", var.c_str());
		return 1;
	}

	size_t setsize = ref->expanded.size();
	auto i = ref->expanded.begin();

	if (setsize > 1) {
		expanded_name += "{";
	}

	do {
		std::string s = *i;
		if (filter_leading_slash)
			trim_leading_slash(s);
		if (filter_trailing_slash)
			trim_trailing_slash(s);

		if (i != ref->expanded.begin()) {
			expanded_name += ",";
		}

		expanded_name += s;
	} while (++i != ref->expanded.end());

	if (setsize > 1) {
		expanded_name += "}";
	}

	expanded_name = prefix + expanded_name + suffix;
	*name = strdup(expanded_name.c_str());
	if (!*name) {
		errno = ENOMEM;
		return -1;
	}
	/* recursive until no variables are found in *name */
	return expand_by_alternation(name);
}

int variable::expand_variable()
{
	char *name = NULL;
	int rc = 0;

	if (type == sd_boolean) {
		PERROR("Referenced variable %s is a boolean used in set context\n",
		       var_name.c_str());
		return 2;
	}

	/* already done */
	if (!expanded.empty())
		return 0;

	expanding = true;

	std::list<std::string> work_set(values.begin(), values.end());
	for (const auto &value : work_set) {
		auto result = extract_variable(value);
		std::string prefix = std::get<0>(result);
		std::string var = std::get<1>(result);
		std::string suffix = std::get<2>(result);

		if (prefix.empty() && var.empty() && suffix.empty()) {
			expanded.insert(value); /* no var left to expand */
			continue;
		}
		name = variable::process_var(var.c_str());
		variable *ref = symtab::lookup_existing_symbol(name);
		if (!ref) {
			PERROR("Failed to find declaration for: %s\n", var.c_str());
			rc = 1;
			goto out;
		}
		if (ref->expanding) {
			PERROR("Variable @{%s} is referenced recursively (by @{%s})\n",
			       ref->var_name.c_str(), var_name.c_str());
			rc = 1;
			goto out;
		}
		rc = ref->expand_variable();
		if (rc != 0) {
			goto out;
		}

		if (ref->expanded.empty()) {
			PERROR("ASSERT: Variable @{%s} should have been expanded but isn't\n",
			       ref->var_name.c_str());
			exit(1);
		}
		for (const auto &refvalue : ref->expanded) {
			/* there could still be vars in suffix, so add
			 * to work_set, not expanded */
			work_set.push_back(prefix + refvalue + suffix);
		}
	}

out:
	free(name);
	expanding = false;
	return rc;
}

void variable::dump_set_values(std::set<std::string> values)
{
	for (const auto &value : values)
		printf(" \"%s\"", value.c_str());
}

void variable::dump(bool do_expanded)
{
	switch(type) {
	case sd_boolean:
		printf("$%s = %s\n", var_name.c_str(),
		       boolean ?  "true" : "false");
		break;
	case sd_set:
		printf("@%s =", var_name.c_str());
		if (do_expanded) {
			if (expanded.empty()) {
				expand_variable();
			}
			dump_set_values(expanded);
		} else {
			dump_set_values(values);
		}
		printf("\n");
		break;
	default:
		PERROR("ASSERT: unknown symbol table type for %s\n", var_name.c_str());
		exit(1);
	}
}
