%{
/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *   Copyright (c) 2010-2012
 *   Canonical Ltd.
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
 *   along with this program; if not, contact Canonical, Ltd.
 */

#define YYERROR_VERBOSE 1
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/apparmor.h>

#include <iostream>

/* #define DEBUG */

#include "capability.h"
#include "lib.h"
#include "parser.h"
#include "profile.h"
#include "mount.h"
#include "dbus.h"
#include "af_unix.h"
#include "parser_include.h"
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

#define CIDR_32 htonl(0xffffffff)
#define CIDR_24 htonl(0xffffff00)
#define CIDR_16 htonl(0xffff0000)
#define CIDR_8  htonl(0xff000000)

/* undefine linux/capability.h CAP_TO_MASK */
#ifdef CAP_TO_MASK
#undef CAP_TO_MASK
#endif

#define CAP_TO_MASK(x) (1ull << (x))

#define EXEC_MODE_EMPTY		0
#define EXEC_MODE_UNSAFE	1
#define EXEC_MODE_SAFE		2

int parser_token = 0;

struct cod_entry *do_file_rule(char *id, perm32_t perms, char *link_id, char *nt);
mnt_rule *do_mnt_rule(struct cond_entry *src_conds, char *src,
		      struct cond_entry *dst_conds, char *dst,
		      perm32_t perms);
mnt_rule *do_pivot_rule(struct cond_entry *old, char *root,
			char *transition);
static void abi_features(char *filename, bool search);

%}

%token TOK_ID
%token TOK_CONDID
%token TOK_CONDLISTID
%token TOK_CARET
%token TOK_OPEN
%token TOK_CLOSE
%token TOK_MODE
%token TOK_END_OF_RULE
%token TOK_EQUALS
%token TOK_ARROW
%token TOK_ADD_ASSIGN
%token TOK_LE
%token TOK_SET_VAR
%token TOK_BOOL_VAR
%token TOK_VALUE
%token TOK_IF
%token TOK_ELSE
%token TOK_NOT
%token TOK_DEFINED
%token TOK_CHANGE_PROFILE
%token TOK_NETWORK
%token TOK_UNIX
%token TOK_CREATE
%token TOK_SHUTDOWN
%token TOK_ACCEPT
%token TOK_CONNECT
%token TOK_LISTEN
%token TOK_SETOPT
%token TOK_GETOPT
%token TOK_SETATTR
%token TOK_GETATTR
%token TOK_HAT
%token TOK_UNSAFE
%token TOK_SAFE
%token TOK_COLON
%token TOK_LINK
%token TOK_OWNER
%token TOK_OTHER
%token TOK_SUBSET
%token TOK_AUDIT
%token TOK_DENY
%token TOK_ALLOW
%token TOK_PROMPT
%token TOK_PROFILE
%token TOK_SET
%token TOK_ALIAS
%token TOK_PTRACE
%token TOK_OPENPAREN
%token TOK_CLOSEPAREN
%token TOK_COMMA
%token TOK_FILE
%token TOK_MOUNT
%token TOK_REMOUNT
%token TOK_UMOUNT
%token TOK_PIVOTROOT
%token TOK_IN
%token TOK_DBUS
%token TOK_SIGNAL
%token TOK_SEND
%token TOK_RECEIVE
%token TOK_BIND
%token TOK_READ
%token TOK_WRITE
%token TOK_EAVESDROP
%token TOK_PEER
%token TOK_TRACE
%token TOK_TRACEDBY
%token TOK_READBY
%token TOK_ABI
%token TOK_USERNS
%token TOK_MQUEUE
%token TOK_DELETE
%token TOK_IO_URING
%token TOK_OVERRIDE_CREDS
%token TOK_SQPOLL
%token TOK_ALL
%token TOK_PRIORITY

 /* rlimits */
%token TOK_RLIMIT
%token TOK_SOFT_RLIMIT
%token TOK_RLIMIT_CPU
%token TOK_RLIMIT_FSIZE
%token TOK_RLIMIT_DATA
%token TOK_RLIMIT_STACK
%token TOK_RLIMIT_CORE
%token TOK_RLIMIT_RSS
%token TOK_RLIMIT_NOFILE
%token TOK_RLIMIT_OFILE
%token TOK_RLIMIT_AS
%token TOK_RLIMIT_NPROC
%token TOK_RLIMIT_MEMLOCK
%token TOK_RLIMIT_LOCKS
%token TOK_RLIMIT_SIGPENDING
%token TOK_RLIMIT_MSGQUEUE
%token TOK_RLIMIT_NICE
%token TOK_RLIMIT_RTPRIO

/* capabilities */
%token TOK_CAPABILITY

/* debug flag values */
%token TOK_FLAGS

%code requires {
	#include "parser.h"
	#include "profile.h"
	#include "mount.h"
	#include "dbus.h"
	#include "signal.h"
	#include "ptrace.h"
	#include "af_unix.h"
	#include "userns.h"
	#include "mqueue.h"
	#include "io_uring.h"
	#include "network.h"
	#include "all_rule.h"
	#include "cond_expr.h"
}

%union {
	char *id;
	char *flag_id;
	char *mode;
	network_rule *network_entry;
	Profile *prof;
	struct cod_net_entry *net_entry;
	struct cod_entry *user_entry;

	mnt_rule *mnt_entry;
	dbus_rule *dbus_entry;
	signal_rule *signal_entry;
	ptrace_rule *ptrace_entry;
	unix_rule *unix_entry;
	userns_rule *userns_entry;
	mqueue_rule *mqueue_entry;
	io_uring_rule *io_uring_entry;
	all_rule *all_entry;
	prefix_rule_t *prefix_entry;

	flagvals flags;
	perm32_t fperms;
	uint64_t cap;
	unsigned int allowed_protocol;
	char *set_var;
	char *bool_var;
	char *var_val;
	struct value_list *val_list;
	struct cond_entry *cond_entry;
	struct cond_entry_list cond_entry_list;
	bool boolean;
	int integer;
	owner_t owner;
	struct prefixes prefix;
	IncludeCache_t *includecache;
	audit_t audit;
	rule_mode_t rule_mode;
	cond_expr *cond;
}

%type <id> 	TOK_ID
%type <id>	TOK_CONDID
%type <id>	TOK_CONDLISTID
%type <mode> 	TOK_MODE
%type <fperms>   file_perms
%type <prof>	profile_base
%type <prof> 	profile
%type <prof>	rules
%type <prof>	block
%type <prof>	hat
%type <prof>	local_profile
%type <prof>	cond_rule
%type <network_entry> network_rule
%type <user_entry> rule
%type <user_entry> file_rule
%type <user_entry> file_rule_tail
%type <user_entry> link_rule
%type <user_entry> frule
%type <mnt_entry> mnt_rule
%type <cond_entry> opt_conds
%type <cond_entry> cond
%type <cond_entry_list> cond_list
%type <cond_entry_list> opt_cond_list
%type <flags>	flags
%type <flags>	flagvals
%type <flags>	flagval
%type <cap>	caps
%type <cap>	capability
%type <user_entry> change_profile
%type <set_var> TOK_SET_VAR
%type <bool_var> TOK_BOOL_VAR
%type <var_val>	TOK_VALUE
%type <val_list> valuelist
%type <cond> expr
%type <id>	id_or_var
%type <id>	opt_id_or_var
%type <boolean> opt_subset_flag
%type <integer>	opt_priority
%type <audit>	opt_audit_flag
%type <owner> opt_owner_flag
%type <integer> opt_profile_flag
%type <boolean> opt_flags
%type <rule_mode> opt_rule_mode
%type <id>	opt_id
%type <prefix>  opt_prefix
%type <fperms>	dbus_perm
%type <fperms>	dbus_perms
%type <fperms>	opt_dbus_perm
%type <dbus_entry>	dbus_rule
%type <prefix_entry>	prefix_rule
%type <fperms>	signal_perm
%type <fperms>	signal_perms
%type <fperms>	opt_signal_perm
%type <signal_entry>	signal_rule
%type <fperms>	ptrace_perm
%type <fperms>	ptrace_perms
%type <fperms>	opt_ptrace_perm
%type <ptrace_entry>	ptrace_rule
%type <fperms>	net_perm
%type <fperms>	net_perms
%type <fperms>	opt_net_perm
%type <unix_entry>	unix_rule
%type <id>	opt_target
%type <id>	opt_named_transition
%type <integer> opt_exec_mode
%type <boolean> opt_file
%type <fperms>  userns_perm
%type <fperms>  userns_perms
%type <fperms>	opt_userns_perm
%type <userns_entry>	userns_rule
%type <fperms>  mqueue_perm
%type <fperms>  mqueue_perms
%type <fperms>	opt_mqueue_perm
%type <mqueue_entry>	mqueue_rule
%type <fperms>	io_uring_perm
%type <fperms>	io_uring_perms
%type <fperms>	opt_io_uring_perm
%type <io_uring_entry>	io_uring_rule
%type <all_entry>	all_rule
%%


list:	 preamble
	{
		/* make sure abi is setup */
		if (override_features) {
			if (policy_features)
				aa_features_unref(policy_features);
			policy_features = aa_features_ref(override_features);
		} else if (policy_features == NULL) {
			if (pinned_features) {
				policy_features = aa_features_ref(pinned_features);
			/* use default feature abi */
			} else {
				if (aa_features_new_from_string(&policy_features,
								default_features_abi,
								strlen(default_features_abi))) {
					yyerror(_("Failed to setup default policy feature abi"));
				}
				pwarn(WARN_ABI, _("%s: File '%s' missing feature abi, falling back to default policy feature abi\n"), progname, current_filename);
			}
		}
		if (!add_cap_feature_mask(policy_features,
					  CAPFLAG_POLICY_FEATURE))
			yyerror(_("Failed to add policy capabilities to known capabilities set"));
		set_supported_features();

	}
	profilelist;

profilelist:	{ /* nothing */ };

profilelist:	profilelist profile
	{
		PDEBUG("Matched: list profile\n");
		add_to_list($2);
	};

opt_profile_flag: { /* nothing */ $$ = 0; }
	| TOK_PROFILE { $$ = 1; }
	| hat_start { $$ = 2; }

opt_id: { /* nothing */ $$ = NULL; }
	| TOK_ID { $$ = $1; }

opt_id_or_var: { /* nothing */ $$ = NULL; }
	| id_or_var { $$ = $1; }

profile_base: TOK_ID opt_id_or_var opt_cond_list flags TOK_OPEN
	{
		/* mid rule action
		 * save current cache, restore at end of block
		 */
		$<includecache>$ = g_includecache;
		g_includecache = new IncludeCache_t();
	}
    rules TOK_CLOSE
	{
		Profile *prof = $7;
		bool self_stack = false;

		if (!prof) {
			yyerror(_("Memory allocation error."));
		}

		parse_label(&self_stack, &prof->ns, &prof->name, $1, true);
		free($1);

		if (self_stack) {
			yyerror(_("Profile names must begin with a '/' or a namespace"));
		}

		/* Honor the --namespace-string command line option */
		if (profile_ns) {
			/**
			 * Print warning if the profile specified a namespace
			 * different than the one specified with the
			 * --namespace-string command line option
			 */
			if (prof->ns && strcmp(prof->ns, profile_ns))
				pwarn(WARN_OVERRIDE, "%s: -n %s overriding policy specified namespace :%s:\n",
				      progname, profile_ns, prof->ns);

			free(prof->ns);
			prof->ns = strdup(profile_ns);
			if (!prof->ns)
				yyerror(_("Memory allocation error."));
		}

		prof->attachment = $2;
		if ($2 && !($2[0] == '/' || strncmp($2, "@{", 2) == 0))
			yyerror(_("Profile attachment must begin with a '/' or variable."));
		if ($3.name) {
			if (strcmp($3.name, "xattrs") != 0)
				yyerror(_("profile id: invalid conditional group %s=()"), $3.name);
			free ($3.name);
			$3.name = NULL;
			prof->xattrs = $3;
		}
		prof->flags = $4;
		if (force_complain && kernel_abi_version == 5)
			/* newer abis encode force complain as part of the
			 * header
			 */
			prof->flags.mode = MODE_COMPLAIN;

		prof->post_parse_profile();
		prof->flags.debug(cerr);

		/* restore previous blocks include cache */
		delete g_includecache;
		g_includecache = $<includecache>6;
		$$ = prof;

	};

profile:  opt_profile_flag profile_base
	{
		Profile *prof = $2;

		if ($2->ns)
			PDEBUG("Matched: :%s://%s { ... }\n", $2->ns, $2->name);
		else
			PDEBUG("Matched: %s { ... }\n", $2->name);

		if ($2->name[0] == '/')
			pwarn(WARN_DEPRECATED, _("The use of file paths as profile names is deprecated. See man apparmor.d for more information\n"));

		if ($2->name[0] != '/' && !($1 || $2->ns))
			yyerror(_("Profile names must begin with a '/', namespace or keyword 'profile' or 'hat'."));

		if ($1 == 2)
			prof->flags.flags |= FLAG_HAT;
		$$ = prof;
	};

local_profile:   TOK_PROFILE profile_base
	{

		Profile *prof = $2;

		if ($2)
			PDEBUG("Matched: local profile %s { ... }\n", prof->name);
		$$ = prof;
	};

hat: hat_start profile_base
	{
		Profile *prof = $2;
		if ($2)
			PDEBUG("Matched: hat %s { ... }\n", prof->name);
		/*
		 * It isn't clear what a xattrs match on a hat profile
		 * should do, disallow it for now.
		 */
		if ($2->xattrs.list)
			yyerror("hat profiles can't use xattrs matches");

		prof->flags.flags |= FLAG_HAT;
		$$ = prof;
	};

preamble: { /* nothing */ }
	| preamble alias { /* nothing */ };
	| preamble varassign { /* nothing */ };
	| preamble abi_rule { /* nothing */ };

alias: TOK_ALIAS TOK_ID TOK_ARROW TOK_ID TOK_END_OF_RULE
	{
		if (!new_alias($2, $4))
			yyerror(_("Failed to create alias %s -> %s\n"), $2, $4);
		free($2);
		free($4);
	};

varassign:	TOK_SET_VAR TOK_EQUALS valuelist
	{
		struct value_list *list = $3;
		char *var_name = process_var($1);
		int err;
		if (!list || !list->value)
			yyerror("Assert: valuelist returned NULL");
		PDEBUG("Matched: set assignment for (%s)\n", $1);
		err = new_set_var(var_name, list->value);
		if (err) {
			free(var_name);
			yyerror("variable %s was previously declared", $1);
			/* FIXME: it'd be handy to report the previous location */
		}
		for (list = list->next; list; list = list->next) {
			err = add_set_value(var_name, list->value);
			if (err) {
				free(var_name);
				yyerror("Error adding %s to set var %s",
					list->value, $1);
			}
		}
		free_value_list($3);
		free(var_name);
		free($1);
	}

varassign:	TOK_SET_VAR TOK_ADD_ASSIGN valuelist
	{
		struct value_list *list = $3;
		char *var_name = process_var($1);
		int err;
		if (!list || !list->value)
			yyerror("Assert: valuelist returned NULL");
		PDEBUG("Matched: additive assignment for (%s)\n", $1);
		/* do the first one outside the loop, subsequent
		 * failures are indicative of symtab failures */
		err = add_set_value(var_name, list->value);
		if (err) {
			free(var_name);
			yyerror("variable %s was not previously declared, but is being assigned additional values", $1);
		}
		for (list = list->next; list; list = list->next) {
			err = add_set_value(var_name, list->value);
			if (err) {
				free(var_name);
				yyerror("Error adding %s to set var %s",
					list->value, $1);
			}
		}
		free_value_list($3);
		free(var_name);
		free($1);
	}

varassign:	TOK_BOOL_VAR TOK_EQUALS TOK_VALUE
	{
		int boolean, err;
		char *var_name = process_var($1);
		PDEBUG("Matched: boolean assignment (%s) to %s\n", $1, $3);
		boolean = str_to_boolean($3);
		if (boolean == -1) {
			yyerror("Invalid boolean assignment for (%s): %s is not true or false",
				$1, $3);
		}
		err = add_boolean_var(var_name, boolean);
		free(var_name);
		if (err) {
			yyerror("variable %s was previously declared", $1);
			/* FIXME: it'd be handy to report the previous location */
		}
		free($1);
		free($3);
	}

valuelist:	TOK_VALUE
	{
		struct value_list *val = new_value_list($1);
		if (!val)
			yyerror(_("Memory allocation error."));
		PDEBUG("Matched: value (%s)\n", $1);

		$$ = val;
	}

valuelist:	valuelist TOK_VALUE
	{
		struct value_list *val = new_value_list($2);
		if (!val)
			yyerror(_("Memory allocation error."));
		PDEBUG("Matched: value list\n");

		list_append($1, val);
		$$ = $1;
	}

flags:	{ /* nothing */
		flagvals fv;

		fv.init();
		$$ = fv;
	};

opt_flags: { /* nothing */ $$ = false; }
	| TOK_CONDID TOK_EQUALS
	{
		if (strcmp($1, "flags") != 0)
			yyerror("expected flags= got %s=", $1);
		free($1);
		$$ = true;
	}

flags:	opt_flags TOK_OPENPAREN flagvals TOK_CLOSEPAREN
	{
		$$ = $3;
	};

flagvals:	flagvals flagval
	{
		$1.merge($2);
		$$ = $1;
	};

flagvals:	flagval
	{
		$$ = $1;
	};

flagval:	TOK_VALUE
	{
		flagvals fv;

		fv.init($1);
		free($1);
		$$ = fv;
	};

opt_subset_flag: { /* nothing */ $$ = false; }
	| TOK_SUBSET { $$ = true; }
	| TOK_LE { $$ = true; }


opt_priority: { $$ = 0; }
	| TOK_PRIORITY TOK_EQUALS TOK_VALUE
	{
		char *end;
		long tmp = strtol($3, &end, 10);
		if (end == $3 || *end != '\0')
			yyerror("invalid priority %s", $3);
		free($3);
		/* see note on mediates_priority */
		if (tmp > MAX_POLICY_PRIORITY)
			yyerror("invalid priority %l > %d", tmp, MAX_POLICY_PRIORITY);
		if (tmp < MIN_POLICY_PRIORITY)
			yyerror("invalid priority %l > %d", tmp, MIN_POLICY_PRIORITY);
		$$ = tmp;
	}

opt_audit_flag: { /* nothing */ $$ = AUDIT_UNSPECIFIED; }
	| TOK_AUDIT { $$ = AUDIT_FORCE; };

opt_owner_flag: { /* nothing */ $$ = OWNER_UNSPECIFIED; }
	| TOK_OWNER { $$ = OWNER_SPECIFIED; };
	| TOK_OTHER { $$ = OWNER_NOT; };

opt_rule_mode: { /* nothing */ $$ = RULE_UNSPECIFIED; }
	| TOK_ALLOW { $$ = RULE_ALLOW; }
	| TOK_DENY { $$ = RULE_DENY; }
	| TOK_PROMPT { $$ = RULE_PROMPT; }

opt_prefix: opt_priority opt_audit_flag opt_rule_mode opt_owner_flag
	{
		$$.priority = $1;
		$$.audit = $2;
		$$.rule_mode = $3;
		$$.owner = $4;
	}

rules:	{ /* nothing */ 
	Profile *prof = new Profile();
		if (!prof) {
			yyerror(_("Memory allocation error."));
		}

		$$ = prof;
	};

rules: rules abi_rule { /* nothing */ }

rules:  rules opt_prefix rule
	{
		const char *error;
		PDEBUG("matched: rules rule\n");
		PDEBUG("rules rule: (%s)\n", $3->name);
		if (!$3)
			yyerror(_("Assert: `rule' returned NULL."));
		if (!entry_add_prefix($3, $2, error)) {
			yyerror(_("%s"), error);
		}
		add_entry_to_policy($1, $3);
		$$ = $1;
	};

block: TOK_OPEN rules TOK_CLOSE
	{
		$$ = $2;
	};

rules: rules opt_prefix block
	{
		struct cod_entry *entry, *tmp;

		if (($2).priority != 0) {
			yyerror(_("priority is not allowed on rule blocks"));
		}
		PDEBUG("matched: %s%s%s%sblock\n",
		       $2.audit == AUDIT_FORCE ? "audit " : "",
		       $2.rule_mode == RULE_DENY ? "deny " : "",
		       $2.rule_mode == RULE_PROMPT ? "prompt " : "",
		       $2.owner == OWNER_SPECIFIED ? "owner " : "");
		list_for_each_safe($3->entries, entry, tmp) {
			const char *error;
			entry->next = NULL;
			if (!entry_add_prefix(entry, $2, error)) {
				yyerror(_("%s"), error);
			}
			/* transfer rule for now, TODO keep block and just
			 * apply add_prefix to block rule and have it do
			 * the work
			 */
			add_entry_to_policy($1, entry);
		}
		$3->entries = NULL;
		// fix me transfer rules and free sub profile
		delete $3;
		$$ = $1;
	};

rules: rules opt_prefix network_rule
	{
		const char *error;
		if (!$3->add_prefix($2, error))
			yyerror(error);
		/* class members need to be updated after prefix is added */
		$3->update_compat_net();

		auto nm_af_unix = $3->network_map.find(AF_UNIX);
		if (nm_af_unix != $3->network_map.end()) {
			for (auto& entry : nm_af_unix->second) {
				unix_rule *rule = new unix_rule(entry.type,
								$2.audit, $2.rule_mode);
				if (!rule)
					yyerror(_("Memory allocation error."));
				$1->rule_ents.push_back(rule);
			}
		}
		$1->rule_ents.push_back($3);
		$$ = $1;
	}

prefix_rule : mnt_rule { $$ = $1; }
	| dbus_rule { $$ = $1; }
	| signal_rule { $$ = $1; }
	| ptrace_rule { $$ = $1; }
	| unix_rule { $$ = $1; }
	| userns_rule { $$ = $1; }
	| mqueue_rule { $$ = $1; }
	| io_uring_rule { $$ = $1; }
	| all_rule { $$ = $1; }

rules:  rules opt_prefix prefix_rule
	{
		const char *error;
		if (!$3->add_prefix($2, error))
			yyerror(error);
		$1->rule_ents.push_back($3);
		$$ = $1;
	}

rules:	rules opt_prefix change_profile
	{
		PDEBUG("matched: rules change_profile\n");
		PDEBUG("rules change_profile: (%s)\n", $3->name);
		if (!$3)
			yyerror(_("Assert: `change_profile' returned NULL."));
		if ($2.owner != OWNER_UNSPECIFIED)
			yyerror(_("owner conditional not allowed on unix rules"));
		if (($2.rule_mode == RULE_DENY) && $2.audit == AUDIT_FORCE) {
			$3->rule_mode = RULE_DENY;
		} else if ($2.rule_mode == RULE_DENY) {
			$3->rule_mode = RULE_DENY;
			$3->audit = AUDIT_FORCE;
		} else if ($2.audit != AUDIT_UNSPECIFIED) {
			$3->audit = $2.audit;
		}
		add_entry_to_policy($1, $3);
		$$ = $1;
	};

rules:  rules opt_prefix capability
	{
		if ($2.owner != OWNER_UNSPECIFIED)
			yyerror(_("owner conditional not allowed on capability rules"));

		if ($2.rule_mode == RULE_DENY && $2.audit == AUDIT_FORCE) {
			$1->caps.deny |= $3;
		} else if ($2.rule_mode == RULE_DENY) {
			$1->caps.deny |= $3;
			$1->caps.quiet |= $3;
		} else {
			$1->caps.allow |= $3;
			if ($2.audit != AUDIT_UNSPECIFIED)
				$1->caps.audit |= $3;
		}

		$$ = $1;
	};

rules:	rules hat
	{
		PDEBUG("Matched: hat rule\n");
		if (!$2)
			yyerror(_("Assert: 'hat rule' returned NULL."));
		add_hat_to_policy($1, $2);
		$$ = $1;
	};

rules:	rules local_profile
	{
		PDEBUG("Matched: hat rule\n");
		if (!$2)
			yyerror(_("Assert: 'local_profile rule' returned NULL."));
		add_hat_to_policy($1, $2);
		$$ = $1;
	};

rules:	rules cond_rule
	{
		PDEBUG("Matched: conditional rules\n");
		$$ = merge_policy($1, $2);
	}

rules: rules TOK_SET TOK_RLIMIT TOK_ID TOK_LE TOK_VALUE opt_id TOK_END_OF_RULE
	{
		rlim_t value = RLIM_INFINITY;
		long long tmp;
		char *end;

		int limit = get_rlimit($4);
		if (limit == -1)
			yyerror("INVALID RLIMIT '%s'\n", $4);

		if (strcmp($6, "infinity") == 0) {
			value = RLIM_INFINITY;
		} else {
			const char *kb = "KB";
			const char *mb = "MB";
			const char *gb = "GB";

			tmp = strtoll($6, &end, 0);
			switch (limit) {
			case RLIMIT_CPU:
				if (!end || $6 == end || tmp < 0)
					yyerror("RLIMIT '%s' invalid value %s\n", $4, $6);
				tmp = convert_time_units(tmp, SECONDS_P_MS, $7);
				if (tmp == -1LL)
					yyerror("RLIMIT '%s %s' < minimum value of 1s\n", $4, $6);
				else if (tmp < 0LL)
					yyerror("RLIMIT '%s' invalid value %s\n", $4, $6);
				if (!$7)
					pwarn(WARN_MISSING, _("RLIMIT 'cpu' no units specified using default units of seconds\n"));
				value = tmp;
				break;
#ifdef RLIMIT_RTTIME
			case RLIMIT_RTTIME:
				/* RTTIME is measured in microseconds */
				if (!end || $6 == end || tmp < 0)
					yyerror("RLIMIT '%s' invalid value %s %s\n", $4, $6, $7 ? $7 : "");
				tmp = convert_time_units(tmp, 1LL, $7);
				if (tmp < 0LL)
					yyerror("RLIMIT '%s' invalid value %s %s\n", $4, $6, $7 ? $7 : "");
				if (!$7)
					pwarn(WARN_MISSING, _("RLIMIT 'rttime' no units specified using default units of microseconds\n"));
				value = tmp;
				break;
#endif
			case RLIMIT_NOFILE:
			case RLIMIT_NPROC:
			case RLIMIT_LOCKS:
			case RLIMIT_SIGPENDING:
#ifdef RLIMIT_RTPRIO
			case RLIMIT_RTPRIO:
				if (!end || $6 == end || $7 || tmp < 0)
					yyerror("RLIMIT '%s' invalid value %s %s\n", $4, $6, $7 ? $7 : "");
				value = tmp;
				break;
#endif
#ifdef RLIMIT_NICE
			case RLIMIT_NICE:
				if (!end || $6 == end || $7)
					yyerror("RLIMIT '%s' invalid value %s %s\n", $4, $6, $7 ? $7 : "");
				if (tmp < -20 || tmp > 19)
					yyerror("RLIMIT '%s' out of range (-20 .. 19) %d\n", $4, tmp);
				value = tmp + 20;
				break;
#endif
			case RLIMIT_FSIZE:
			case RLIMIT_DATA:
			case RLIMIT_STACK:
			case RLIMIT_CORE:
			case RLIMIT_RSS:
			case RLIMIT_AS:
			case RLIMIT_MEMLOCK:
			case RLIMIT_MSGQUEUE:
				if ($6 == end || tmp < 0)
					yyerror("RLIMIT '%s' invalid value %s %s\n", $4, $6, $7 ? $7 : "");
				if (!$7) {
					; /* use default of bytes */
				} else if (strstr(kb, $7) == kb) {
					tmp *= 1024;
				} else if (strstr(mb, $7) == mb) {
					tmp *= 1024*1024;
				} else if (strstr(gb, $7) == gb) {
					tmp *= 1024*1024*1024;
				} else {
					yyerror("RLIMIT '%s' invalid value %s %s\n", $4, $6, $7);
				}
				value = tmp;
				break;
			default:
				yyerror("Unknown RLIMIT %d\n", $4);
			}
		}
		$1->rlimits.specified |= 1 << limit;
		$1->rlimits.limits[limit] = value;
		free($4);
		free($6);
		$$ = $1;
	};


cond_rule: TOK_IF expr block
	{
		Profile *ret = NULL;
		PDEBUG("Matched: found conditional rules\n");
		if ($2->eval()) {
			ret = $3;
		} else {
			delete $3;
		}
		delete $2;
		$$ = ret;
	}

cond_rule: TOK_IF expr block TOK_ELSE block
	{
		Profile *ret = NULL;
		PDEBUG("Matched: found conditional else rules\n");
		if ($2->eval()) {
			ret = $3;
			delete $5;
		} else {
			ret = $5;
			delete $3;
		}
		delete $2;
		$$ = ret;
	}

cond_rule: TOK_IF expr block TOK_ELSE cond_rule
	{
		Profile *ret = NULL;
		PDEBUG("Matched: found conditional else-if rules\n");
		if ($2->eval()) {
			ret = $3;
			delete $5;
		} else {
			ret = $5;
			delete $3;
		}
		delete $2;
		$$ = ret;
	}

expr:	TOK_NOT expr
	{
		cond_expr *conds = new cond_expr(!$2->eval());
		delete $2;
		$$ = conds;
	}

expr:	TOK_BOOL_VAR
	{
		cond_expr *conds = new cond_expr($1, false);
		PDEBUG("Matched: boolean expr %s value: %d\n", $1, conds->eval());
		$$ = conds;
		free($1);
	}

expr:	TOK_DEFINED TOK_SET_VAR
	{
		cond_expr *conds = new cond_expr($2, true);
		PDEBUG("Matched: defined set expr %s value %d\n", $2, conds->eval());
		$$ = conds;
		free($2);
	}

expr:	TOK_DEFINED TOK_BOOL_VAR
	{
		cond_expr *conds = new cond_expr($2, false);
		PDEBUG("Matched: defined set expr %s value %d\n", $2, conds->eval());
		$$ = conds;
		free($2);
	}

id_or_var: TOK_ID { $$ = $1; }
id_or_var: TOK_SET_VAR { $$ = $1; };

opt_target: /* nothing */ { $$ = NULL; }
opt_target: TOK_ARROW id_or_var { $$ = $2; };

opt_named_transition: { /* nothing */ $$ = NULL; }
	| TOK_ARROW id_or_var
	{
		$$ = $2;
	};

rule: file_rule { $$ = $1; }
	| link_rule { $$ = $1; }

abi_rule: TOK_ABI TOK_ID TOK_END_OF_RULE
	{
		abi_features($2, true);
		free($2);
		/* $$ = nothing, not used */
	}
	| TOK_ABI TOK_VALUE TOK_END_OF_RULE
	{
		abi_features($2, false);
		free($2);
		/* $$ = nothing, not used */
	}

opt_exec_mode: { /* nothing */ $$ = EXEC_MODE_EMPTY; }
	| TOK_UNSAFE { $$ = EXEC_MODE_UNSAFE; };
	| TOK_SAFE { $$ = EXEC_MODE_SAFE; };

opt_file: { /* nothing */ $$ = false; }
	| TOK_FILE { $$ = true; }

frule:	id_or_var file_perms opt_named_transition TOK_END_OF_RULE
	{
		$$ = do_file_rule($1, $2, NULL, $3);
	};

frule:	file_perms opt_subset_flag id_or_var opt_named_transition TOK_END_OF_RULE
	{
		if ($2 && ($1 & ~AA_LINK_BITS))
			yyerror(_("subset can only be used with link rules."));
		if ($4 && ($1 & AA_LINK_BITS) && ($1 & AA_EXEC_BITS))
			yyerror(_("link and exec perms conflict on a file rule using ->"));
		if ($4 && label_contains_ns($4) && ($1 & AA_LINK_BITS))
			yyerror(_("link perms are not allowed on a named profile transition.\n"));

		if (($1 & AA_LINK_BITS)) {
			$$ = do_file_rule($3, $1, $4, NULL);
			$$->subset = $2;

		} else {
			$$ = do_file_rule($3, $1, NULL, $4);
		}
 	};

file_rule: TOK_FILE TOK_END_OF_RULE
	{
		char *path = strdup("/{**,}");
		int perms = ((AA_BASE_PERMS & ~AA_EXEC_TYPE) |
			     (AA_EXEC_INHERIT | AA_MAY_EXEC));
		/* duplicate to other permission set */
		perms |= perms << AA_OTHER_SHIFT;
		if (!path)
			yyerror(_("Memory allocation error."));
		$$ = do_file_rule(path, perms, NULL, NULL);
	}
	| opt_file file_rule_tail { $$ = $2; }


file_rule_tail: opt_exec_mode frule
	{
		if ($1 != EXEC_MODE_EMPTY) {
			if (!($2->perms & AA_EXEC_BITS))
				yyerror(_("unsafe rule missing exec permissions"));
			if ($1 == EXEC_MODE_UNSAFE) {
				$2->perms |= (($2->perms & AA_EXEC_BITS) << 8) &
					 ALL_AA_EXEC_UNSAFE;
			}
			else if ($1 == EXEC_MODE_SAFE)
				$2->perms &= ~ALL_AA_EXEC_UNSAFE;
		}
		$$ = $2;
	};

file_rule_tail: opt_exec_mode id_or_var file_perms id_or_var
	{
		/* Oopsie, we appear to be missing an EOL marker. If we
		 * were *smart*, we could work around it. Since we're
		 * obviously not smart, we'll just punt with a more
		 * sensible error. */
		yyerror(_("missing an end of line character? (entry: %s)"), $2);
	};

link_rule: TOK_LINK opt_subset_flag id_or_var TOK_ARROW id_or_var TOK_END_OF_RULE
	{
		struct cod_entry *entry;
		PDEBUG("Matched: link tok_id (%s) -> (%s)\n", $3, $5);
		entry = new_entry($3, AA_LINK_BITS, $5);
		entry->subset = $2;
		PDEBUG("rule.entry: link (%s)\n", entry->name);
		$$ = entry;
	};

network_rule: TOK_NETWORK opt_net_perm opt_conds opt_cond_list TOK_END_OF_RULE
	{
		network_rule *entry;

		if ($4.name) {
			if (strcmp($4.name, "peer") != 0)
				yyerror(_("network rule: invalid conditional group %s=()"), $4.name);
			free($4.name);
		}
		entry = new network_rule($2, $3, $4.list);
		$$ = entry;
	}

network_rule: TOK_NETWORK opt_net_perm TOK_ID opt_conds opt_cond_list TOK_END_OF_RULE
	{
		network_rule *entry;

		if ($5.name) {
			if (strcmp($5.name, "peer") != 0)
				yyerror(_("network rule: invalid conditional group %s=()"), $5.name);
			free($5.name);
		}
		entry = new network_rule($2, $3, NULL, NULL, $4, $5.list);
		free($3);
		$$ = entry;
	}

network_rule: TOK_NETWORK opt_net_perm TOK_ID TOK_ID opt_conds opt_cond_list TOK_END_OF_RULE
	{
		network_rule *entry;

		if ($6.name) {
			if (strcmp($6.name, "peer") != 0)
				yyerror(_("network rule: invalid conditional group %s=()"), $6.name);
			free($6.name);
		}
		entry = new network_rule($2, $3, $4, NULL, $5, $6.list);
		free($3);
		free($4);
		$$ = entry;
	}

cond: TOK_CONDID
	{
		struct cond_entry *ent;
		ent = new_cond_entry($1, 0, NULL);
		if (!ent)
			yyerror(_("Memory allocation error."));
		$$ = ent;
	}

cond: TOK_CONDID TOK_EQUALS TOK_VALUE
	{
		struct cond_entry *ent;
		struct value_list *value = new_value_list($3);
		if (!value)
			yyerror(_("Memory allocation error."));
		ent = new_cond_entry($1, 1, value);
		if (!ent) {
			free_value_list(value);
			yyerror(_("Memory allocation error."));
		}
		$$ = ent;
	}

cond: TOK_CONDID TOK_EQUALS TOK_OPENPAREN valuelist TOK_CLOSEPAREN
	{
		struct cond_entry *ent = new_cond_entry($1, 1, $4);

		if (!ent)
			yyerror(_("Memory allocation error."));
		$$ = ent;
	}


cond: TOK_CONDID TOK_IN TOK_OPENPAREN valuelist TOK_CLOSEPAREN
	{
		struct cond_entry *ent = new_cond_entry($1, 0, $4);

		if (!ent)
			yyerror(_("Memory allocation error."));
		$$ = ent;
	}

opt_conds: { /* nothing */ $$ = NULL; }
	| opt_conds cond
	{
		$2->next = $1;
		$$ = $2;
	}

cond_list: TOK_CONDLISTID TOK_EQUALS TOK_OPENPAREN opt_conds TOK_CLOSEPAREN
	{
		$$.name = $1;
		$$.list = $4;
	}

opt_cond_list: { /* nothing */ $$ = { NULL, NULL }; }
	| cond_list { $$ = $1; }

mnt_rule: TOK_MOUNT opt_conds opt_id TOK_END_OF_RULE
	{
		$$ = do_mnt_rule($2, $3, NULL, NULL, AA_MAY_MOUNT);
	}

mnt_rule: TOK_MOUNT opt_conds opt_id TOK_ARROW opt_conds TOK_ID TOK_END_OF_RULE
	{
		$$ = do_mnt_rule($2, $3, $5, $6, AA_MAY_MOUNT);
	}

mnt_rule: TOK_REMOUNT opt_conds opt_id TOK_END_OF_RULE
	{
		$$ = do_mnt_rule($2, NULL, NULL, $3, AA_DUMMY_REMOUNT);
	}

mnt_rule: TOK_UMOUNT opt_conds opt_id TOK_END_OF_RULE
	{
		$$ = do_mnt_rule($2, NULL, NULL, $3, AA_MAY_UMOUNT);
	}

mnt_rule: TOK_PIVOTROOT opt_conds opt_id opt_target TOK_END_OF_RULE
	{
		$$ = do_pivot_rule($2, $3, $4);
	}

dbus_perm: TOK_VALUE
	{
		if (strcmp($1, "bind") == 0)
			$$ = AA_DBUS_BIND;
		else if (strcmp($1, "send") == 0 || strcmp($1, "write") == 0)
			$$ = AA_DBUS_SEND;
		else if (strcmp($1, "receive") == 0 || strcmp($1, "read") == 0)
			$$ = AA_DBUS_RECEIVE;
		else if (strcmp($1, "eavesdrop") == 0)
			$$ = AA_DBUS_EAVESDROP;
		else if ($1) {
			parse_dbus_perms($1, &$$, 1);
		} else
			$$ = 0;

		if ($1)
			free($1);
	}
	| TOK_BIND { $$ = AA_DBUS_BIND; }
	| TOK_SEND { $$ = AA_DBUS_SEND; }
	| TOK_RECEIVE { $$ = AA_DBUS_RECEIVE; }
	| TOK_READ { $$ = AA_DBUS_RECEIVE; }
	| TOK_WRITE { $$ = AA_DBUS_SEND; }
	| TOK_EAVESDROP { $$ = AA_DBUS_EAVESDROP; }
	| TOK_MODE
	{
		parse_dbus_perms($1, &$$, 1);
		free($1);
	}

dbus_perms: { /* nothing */ $$ = 0; }
	| dbus_perms dbus_perm { $$ = $1 | $2; }
	| dbus_perms TOK_COMMA dbus_perm { $$ = $1 | $3; }

opt_dbus_perm: { /* nothing */ $$ = 0; }
	| dbus_perm  { $$ = $1; }
	| TOK_OPENPAREN dbus_perms TOK_CLOSEPAREN { $$ = $2; }

dbus_rule: TOK_DBUS opt_dbus_perm opt_conds opt_cond_list TOK_END_OF_RULE
	{
		dbus_rule *ent;

		if ($4.name) {
			if (strcmp($4.name, "peer") != 0)
				yyerror(_("dbus rule: invalid conditional group %s=()"), $4.name);
			free($4.name);
		}
		ent = new dbus_rule($2, $3, $4.list);
		if (!ent) {
			yyerror(_("Memory allocation error."));
		}
		$$ = ent;
	}

net_perm: TOK_VALUE
	{
		if (strcmp($1, "create") == 0)
			$$ = AA_NET_CREATE;
		else if (strcmp($1, "bind") == 0)
			$$ = AA_NET_BIND;
		else if (strcmp($1, "listen") == 0)
			$$ = AA_NET_LISTEN;
		else if (strcmp($1, "accept") == 0)
			$$ = AA_NET_ACCEPT;
		else if (strcmp($1, "connect") == 0)
			$$ = AA_NET_CONNECT;
		else if (strcmp($1, "shutdown") == 0)
			$$ = AA_NET_SHUTDOWN;
		else if (strcmp($1, "getattr") == 0)
			$$ = AA_NET_GETATTR;
		else if (strcmp($1, "setattr") == 0)
			$$ = AA_NET_SETATTR;
		else if (strcmp($1, "getopt") == 0)
			$$ = AA_NET_GETOPT;
		else if (strcmp($1, "setopt") == 0)
			$$ = AA_NET_SETOPT;
		else if (strcmp($1, "send") == 0 || strcmp($1, "write") == 0)
			$$ = AA_NET_SEND;
		else if (strcmp($1, "receive") == 0 || strcmp($1, "read") == 0)
			$$ = AA_NET_RECEIVE;
		else if ($1) {
			parse_net_perms($1, &$$, 1);
		} else
			$$ = 0;

		if ($1)
			free($1);
	}
	| TOK_CREATE { $$ = AA_NET_CREATE; }
	| TOK_BIND { $$ = AA_NET_BIND; }
	| TOK_LISTEN { $$ = AA_NET_LISTEN; }
	| TOK_ACCEPT { $$ = AA_NET_ACCEPT; }
	| TOK_CONNECT { $$ = AA_NET_CONNECT; }
	| TOK_SHUTDOWN { $$ = AA_NET_SHUTDOWN; }
	| TOK_GETATTR { $$ = AA_NET_GETATTR; }
	| TOK_SETATTR { $$ = AA_NET_SETATTR; }
	| TOK_GETOPT { $$ = AA_NET_GETOPT; }
	| TOK_SETOPT { $$ = AA_NET_SETOPT; }
	| TOK_SEND { $$ = AA_NET_SEND; }
	| TOK_RECEIVE { $$ = AA_NET_RECEIVE; }
	| TOK_READ { $$ = AA_NET_RECEIVE; }
	| TOK_WRITE { $$ = AA_NET_SEND; }
	| TOK_MODE
	{
		parse_unix_perms($1, &$$, 1);
		free($1);
	}

net_perms: { /* nothing */ $$ = 0; }
	| net_perms net_perm { $$ = $1 | $2; }
	| net_perms TOK_COMMA net_perm { $$ = $1 | $3; }

opt_net_perm: { /* nothing */ $$ = 0; }
	| net_perm  { $$ = $1; }
	| TOK_OPENPAREN net_perms TOK_CLOSEPAREN { $$ = $2; }

unix_rule: TOK_UNIX opt_net_perm opt_conds opt_cond_list TOK_END_OF_RULE
	{
		unix_rule *ent;

		if ($4.name) {
			if (strcmp($4.name, "peer") != 0)
				yyerror(_("unix rule: invalid conditional group %s=()"), $4.name);
			free($4.name);
		}
		ent = new unix_rule($2, $3, $4.list);
		if (!ent) {
			yyerror(_("Memory allocation error."));
		}
		$$ = ent;
	}

signal_perm: TOK_VALUE
	{
		if (strcmp($1, "send") == 0 || strcmp($1, "write") == 0)
			$$ = AA_MAY_SEND;
		else if (strcmp($1, "receive") == 0 || strcmp($1, "read") == 0)
			$$ = AA_MAY_RECEIVE;
		else if ($1) {
			parse_signal_perms($1, &$$, 1);
		} else
			$$ = 0;

		if ($1)
			free($1);
	}
	| TOK_SEND { $$ = AA_MAY_SEND; }
	| TOK_RECEIVE { $$ = AA_MAY_RECEIVE; }
	| TOK_READ { $$ = AA_MAY_RECEIVE; }
	| TOK_WRITE { $$ = AA_MAY_SEND; }
	| TOK_MODE
	{
		parse_signal_perms($1, &$$, 1);
		free($1);
	}

signal_perms: { /* nothing */ $$ = 0; }
	| signal_perms signal_perm { $$ = $1 | $2; }
	| signal_perms TOK_COMMA signal_perm { $$ = $1 | $3; }

opt_signal_perm: { /* nothing */ $$ = 0; }
	| signal_perm { $$ = $1; }
	| TOK_OPENPAREN signal_perms TOK_CLOSEPAREN { $$ = $2; }

signal_rule: TOK_SIGNAL opt_signal_perm opt_conds TOK_END_OF_RULE
	{
		signal_rule *ent = new signal_rule($2, $3);
		$$ = ent;
	}

ptrace_perm: TOK_VALUE
	{
		if (strcmp($1, "trace") == 0 || strcmp($1, "write") == 0)
			$$ = AA_MAY_TRACE;
		else if (strcmp($1, "read") == 0)
			$$ = AA_MAY_READ;
		else if (strcmp($1, "tracedby") == 0)
			$$ = AA_MAY_TRACEDBY;
		else if (strcmp($1, "readby") == 0)
			$$ = AA_MAY_READBY;
		else if ($1)
			parse_ptrace_perms($1, &$$, 1);
		else
			$$ = 0;

		if ($1)
			free($1);
	}
	| TOK_TRACE { $$ = AA_MAY_TRACE; }
	| TOK_TRACEDBY { $$ = AA_MAY_TRACEDBY; }
	| TOK_READ { $$ = AA_MAY_READ; }
	| TOK_WRITE { $$ = AA_MAY_TRACE; }
	| TOK_READBY { $$ = AA_MAY_READBY; }
	| TOK_MODE
	{
		parse_ptrace_perms($1, &$$, 1);
		free($1);
	}

ptrace_perms: { /* nothing */ $$ = 0; }
	| ptrace_perms ptrace_perm { $$ = $1 | $2; }
	| ptrace_perms TOK_COMMA ptrace_perm { $$ = $1 | $3; }

opt_ptrace_perm: { /* nothing */ $$ = 0; }
	| ptrace_perm { $$ = $1; }
	| TOK_OPENPAREN ptrace_perms TOK_CLOSEPAREN { $$ = $2; }

ptrace_rule: TOK_PTRACE opt_ptrace_perm opt_conds TOK_END_OF_RULE
	{
		ptrace_rule *ent = new ptrace_rule($2, $3);
		$$ = ent;
	}

userns_perm: TOK_VALUE
	{
		if (strcmp($1, "create") == 0)
			$$ = AA_USERNS_CREATE;
		else
			$$ = 0;

		if ($1)
			free($1);
	}
	| TOK_CREATE { $$ = AA_USERNS_CREATE; }

userns_perms: { /* nothing */ $$ = 0; }
	| userns_perms userns_perm { $$ = $1 | $2; }
	| userns_perms TOK_COMMA userns_perm { $$ = $1 | $3; }

opt_userns_perm: { /* nothing */ $$ = 0; }
	| userns_perm { $$ = $1; }
	| TOK_OPENPAREN userns_perms TOK_CLOSEPAREN { $$ = $2; }

userns_rule: TOK_USERNS opt_userns_perm opt_conds TOK_END_OF_RULE
	{
		userns_rule *ent = new userns_rule($2, $3);
		$$ = ent;
	}

mqueue_perm: TOK_VALUE
	{
		if (strcmp($1, "create") == 0)
			$$ = AA_MQUEUE_CREATE;
		else if (strcmp($1, "open") == 0)
			$$ = AA_MQUEUE_OPEN;
		else if (strcmp($1, "delete") == 0)
			$$ = AA_MQUEUE_DELETE;
		else if (strcmp($1, "getattr") == 0)
			$$ = AA_MQUEUE_GETATTR;
		else if (strcmp($1, "setattr") == 0)
			$$ = AA_MQUEUE_SETATTR;
		else if (strcmp($1, "write") == 0)
			$$ = AA_MQUEUE_WRITE;
		else if (strcmp($1, "read") == 0)
			$$ = AA_MQUEUE_READ;
		else if ($1) {
			parse_mqueue_perms($1, &$$, 1);
		} else
			$$ = 0;

		if ($1)
			free($1);
	}
	| TOK_CREATE { $$ = AA_MQUEUE_CREATE; }
	| TOK_OPEN { $$ = AA_MQUEUE_OPEN; }
	| TOK_DELETE { $$ = AA_MQUEUE_DELETE; }
	| TOK_GETATTR { $$ = AA_MQUEUE_GETATTR; }
	| TOK_SETATTR { $$ = AA_MQUEUE_SETATTR; }
	| TOK_WRITE { $$ = AA_MQUEUE_WRITE; }
	| TOK_READ { $$ = AA_MQUEUE_READ; }
	| TOK_MODE
	{
		parse_mqueue_perms($1, &$$, 1);
		free($1);
	}

mqueue_perms: { /* nothing */ $$ = 0; }
	| mqueue_perms mqueue_perm { $$ = $1 | $2; }
	| mqueue_perms TOK_COMMA mqueue_perm { $$ = $1 | $3; }

opt_mqueue_perm: { /* nothing */ $$ = 0; }
	| mqueue_perm { $$ = $1; }
	| TOK_OPENPAREN mqueue_perms TOK_CLOSEPAREN { $$ = $2; }

mqueue_rule: TOK_MQUEUE opt_mqueue_perm opt_conds TOK_END_OF_RULE
	{
		mqueue_rule *ent = new mqueue_rule($2, $3);
		$$ = ent;
	}
	| TOK_MQUEUE opt_mqueue_perm opt_conds TOK_ID TOK_END_OF_RULE
	{
		mqueue_rule *ent = new mqueue_rule($2, $3, $4);
		$$ = ent;
	}

io_uring_perm: TOK_VALUE
	{
		if (strcmp($1, "override_creds") == 0)
			$$ = AA_IO_URING_OVERRIDE_CREDS;
		else if (strcmp($1, "sqpoll") == 0)
			$$ = AA_IO_URING_SQPOLL;
		else
			$$ = 0;

		if ($1)
			free($1);
	}
	| TOK_OVERRIDE_CREDS { $$ = AA_IO_URING_OVERRIDE_CREDS; }
	| TOK_SQPOLL { $$ = AA_IO_URING_SQPOLL; }

io_uring_perms: { /* nothing */ $$ = 0; }
	| io_uring_perms io_uring_perm { $$ = $1 | $2; }
	| io_uring_perms TOK_COMMA io_uring_perm { $$ = $1 | $3; }

opt_io_uring_perm: { /* nothing */ $$ = 0; }
	| io_uring_perm { $$ = $1; }
	| TOK_OPENPAREN io_uring_perms TOK_CLOSEPAREN { $$ = $2; }

io_uring_rule: TOK_IO_URING opt_io_uring_perm opt_conds opt_cond_list TOK_END_OF_RULE
	{
		io_uring_rule *ent;
		ent = new io_uring_rule($2, $3, $4.list);
		if (!ent)
			yyerror(_("Memory allocation error."));
		$$ = ent;
	}

all_rule: TOK_ALL TOK_END_OF_RULE
	{
		all_rule *ent = new all_rule();
		if (!ent)
			yyerror(_("Memory allocation error."));
		$$ = ent;
	}

hat_start: TOK_CARET {}
	| TOK_HAT {}

file_perms: TOK_MODE
	{
		/* A single TOK_MODE maps to the same permission in all
		 * of user::other */
		$$ = parse_perms($1);
		free($1);
	}

change_profile: TOK_CHANGE_PROFILE opt_exec_mode opt_id opt_named_transition TOK_END_OF_RULE
	{
		struct cod_entry *entry;
		perm32_t perms = AA_CHANGE_PROFILE;
		int exec_mode = $2;
		char *exec = $3;
		char *target = $4;

		if (exec) {
			/* exec bits required to trigger rule conflict if
			 * for overlapping safe and unsafe exec rules
			 */
			perms |= AA_EXEC_BITS;
			if (exec_mode == EXEC_MODE_UNSAFE)
				perms |= ALL_AA_EXEC_UNSAFE;
			else if (exec_mode == EXEC_MODE_SAFE &&
				 !features_supports_stacking) {
				pwarn(WARN_RULE_DOWNGRADED, "downgrading change_profile safe rule to unsafe due to lack of necessary kernel support\n");
				/**
				 * No need to do anything because 'unsafe' exec
				 * mode is the only supported mode of
				 * change_profile rules in non-stacking kernels
				 */
			}
		} else if (exec_mode != EXEC_MODE_EMPTY)
			yyerror(_("Exec condition is required when unsafe or safe keywords are present"));
		if (exec && !(exec[0] == '/' || strncmp(exec, "@{", 2) == 0))
			yyerror(_("Exec condition must begin with '/'."));

		if (target) {
			PDEBUG("Matched change_profile: tok_id (%s)\n", target);
		} else {
			PDEBUG("Matched change_profile,\n");
			target = strdup("**");
			if (!target)
				yyerror(_("Memory allocation error."));
		}

		entry = new_entry(target, perms, exec);
		if (!entry)
			yyerror(_("Memory allocation error."));

		PDEBUG("change_profile.entry: (%s)\n", entry->name);
		$$ = entry;
	};

capability:	TOK_CAPABILITY caps TOK_END_OF_RULE
	{
		if ($2 == 0) {
			/* bare capability keyword - set all caps */
			$$ = 0xffffffffffffffff;
		} else
			$$ = $2;
	};

caps: { /* nothing */ $$ = 0; }
	| caps TOK_ID
	{
		int backmap, cap = name_to_capability($2);
		if (cap == -1)
			yyerror(_("Invalid capability %s."), $2);
		free($2);
		backmap = capability_backmap(cap);
		if (backmap != NO_BACKMAP_CAP && !capability_in_kernel(cap)) {
			/* TODO: special backmap warning */
			cap = backmap;
		}
		$$ = $1 | CAP_TO_MASK(cap);
	}

%%
#define MAXBUFSIZE 4096

void vprintyyerror(const char *msg, va_list argptr)
{
	char buf[MAXBUFSIZE];

	vsnprintf(buf, sizeof(buf), msg, argptr);

	if (profilename) {
		PERROR(_("AppArmor parser error for %s%s%s at line %d: %s\n"),
		       profilename,
		       current_filename ? " in profile " : "",
		       current_filename ? current_filename : "",
		       current_lineno, buf);
	} else {
		PERROR(_("AppArmor parser error at line %d: %s\n"),
		       current_lineno, buf);
	}
}

void printyyerror(const char *msg, ...)
{
	va_list arg;

	va_start(arg, msg);
	vprintyyerror(msg, arg);
	va_end(arg);
}

void yyerror(const char *msg, ...)
{
	va_list arg;

	va_start(arg, msg);
	vprintyyerror(msg, arg);
	va_end(arg);

	exit(1);
}

struct cod_entry *do_file_rule(char *id, perm32_t perms, char *link_id, char *nt)
{
		struct cod_entry *entry;
		PDEBUG("Matched: tok_id (%s) tok_perms (0x%x)\n", id, perms);
		entry = new_entry(id, perms, link_id);
		if (!entry)
			yyerror(_("Memory allocation error."));
		entry->nt_name = nt;
		PDEBUG("rule.entry: (%s)\n", entry->name);
		return entry;
}

static const char *mnt_cond_msg[] = {"",
			 " not allowed as source conditional",
			 " not allowed as target conditional",
			 "",
			 NULL};

int verify_mnt_conds(struct cond_entry *conds, int src)
{
	struct cond_entry *entry;
	int error = 0;

	if (!conds)
		return 0;

	list_for_each(conds, entry) {
		int res = is_valid_mnt_cond(entry->name, src);
		if (res <= 0) {
				printyyerror(_("invalid mount conditional %s%s"),
					     entry->name,
					     res == -1 ? "" : mnt_cond_msg[src]);
				error++;
		}
	}

	return error;
}

mnt_rule *do_mnt_rule(struct cond_entry *src_conds, char *src,
		      struct cond_entry *dst_conds, char *dst,
		      perm32_t perms)
{
	if (verify_mnt_conds(src_conds, MNT_SRC_OPT) != 0)
		yyerror(_("bad mount rule"));

	/* FIXME: atm conditions are not supported on dst
	if (verify_conds(dst_conds, DST_OPT) != 0)
		yyerror(_("bad mount rule"));
	*/
	if (dst_conds)
		yyerror(_("mount point conditions not currently supported"));

	mnt_rule *ent = new mnt_rule(src_conds, src, dst_conds, dst, perms);
	if (!ent) {
		yyerror(_("Memory allocation error."));
	}

	return ent;
}

mnt_rule *do_pivot_rule(struct cond_entry *old, char *root, char *transition)
{
	char *device = NULL;
	if (old) {
		if (strcmp(old->name, "oldroot") != 0)
			yyerror(_("invalid pivotroot conditional '%s'"), old->name);
		if (old->vals) {
			device = old->vals->value;
			old->vals->value = NULL;
		}
		free_cond_entry(old);
	}

	mnt_rule *ent = new mnt_rule(NULL, device, NULL, root, AA_MAY_PIVOTROOT);
	ent->trans = transition;

	return ent;
}

static int abi_features_base(struct aa_features **features, char *filename, bool search)
{
	autofclose FILE *f = NULL;
	struct stat my_stat;
	autofree char *fullpath = NULL;
	bool cached;

	if (search) {
		if (strcmp(filename, "kernel") == 0) {
			if (kernel_features) {
				*features = aa_features_ref(kernel_features);
				return 0;
			}
			return aa_features_new_from_kernel(features);
		} else if (strcmp(filename, "default") == 0) {
			return aa_features_new_from_string(features,
								default_features_abi,
								strlen(default_features_abi));
		}
		f = search_path(filename, &fullpath, &cached);
		PDEBUG("abi lookup '%s' -> '%s' f %p cached %d\n", filename, fullpath, f, cached);
		if (!f && cached) {
			*features = NULL;
			return 0;
		}
	} else {
		f = fopen(filename, "r");
		PDEBUG("abi relpath '%s' f %p\n", filename, f);
	}

	if (!f) {
		yyerror(_("Could not open '%s': %m"),
                        fullpath ? fullpath: filename);
	}

	if (fstat(fileno(f), &my_stat))
		yyerror(_("fstat failed for '%s': %m"), fullpath ? fullpath : filename);

        if (S_ISREG(my_stat.st_mode)) {
		return aa_features_new_from_file(features, fileno(f));
	}

	return -1;
}

static void abi_features(char *filename, bool search)
{
	struct aa_features *tmp_features;

	if (abi_features_base(&tmp_features, filename, search) == -1) {
			yyerror(_("failed to find features abi '%s': %m"), filename);
	}
	if (policy_features) {
		if (tmp_features) {
			if (!aa_features_is_equal(tmp_features, policy_features)) {
				pwarn(WARN_ABI, _("%s: %s features abi '%s' differs from policy declared feature abi, using the features abi declared in policy\n"), progname, current_filename, filename);
			}
			aa_features_unref(tmp_features);
		}
	} else if (!tmp_features) {
		/* skipped reinclude, but features not set */
		yyerror(_("failed features abi not set but include cache skipped\n"));
	} else {
		/* first features abi declaration */
		policy_features = tmp_features;
	}

};
