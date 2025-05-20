/*
 * (C) 2006, 2007 Andreas Gruenbacher <agruen@suse.de>
 * Copyright (c) 2003-2008 Novell, Inc. (All rights reserved)
 * Copyright 2009-2012 Canonical Ltd.
 *
 * The libapparmor library is licensed under the terms of the GNU
 * Lesser General Public License, version 2.1. Please see the file
 * COPYING.LGPL.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
  * Base of implementation based on the Lexical Analysis chapter of:
 *   Alfred V. Aho, Ravi Sethi, Jeffrey D. Ullman:
 *   Compilers: Principles, Techniques, and Tools (The "Dragon Book"),
 *   Addison-Wesley, 1986.
 */
#ifndef __LIBAA_RE_HFA_H
#define __LIBAA_RE_HFA_H

#include <list>
#include <map>
#include <vector>
#include <iostream>

#include <assert.h>
#include <limits.h>
#include <stdint.h>

#include "expr-tree.h"
#include "policy_compat.h"
#include "../rule.h"
extern int prompt_compat_mode;

#define DiffEncodeFlag 1

class State;

typedef std::map<transchar, State *> StateTrans;
typedef std::list<State *> Partition;

#include "../immunix.h"

ostream &operator<<(ostream &os, const State &state);
ostream &operator<<(ostream &os, State &state);

class perms_t {
public:
	perms_t(void): allow(0), deny(0), prompt(0), audit(0), quiet(0), exact(0) { };

	bool is_accept(void) { return (allow | deny | prompt | audit | quiet); }

	void dump_header(ostream &os)
	{
		os << "(allow/deny/prompt/audit/quiet)";
	}
	ostream &dump(ostream &os)
	{
		os << "(0x " << std::hex
		   << allow << "/" << deny << "/" << "/" << prompt << "/" << audit << "/" << quiet
		   << ')' << std::dec;
		return os;
	}

	void clear(void) {
		allow = deny = prompt = audit = quiet = exact = 0;
	}

	void clear_bits(perm32_t bits)
	{
		allow &= ~bits;
		deny &= ~bits;
		prompt &= ~bits;
		audit &= ~bits;
		quiet &= ~bits;
		exact &= ~bits;
	}

	void add(perms_t &rhs, bool filedfa)
	{
		deny |= rhs.deny;

		if (filedfa && !is_merged_x_consistent(allow & ALL_USER_EXEC,
					    rhs.allow & ALL_USER_EXEC)) {
			if ((exact & AA_USER_EXEC_TYPE) &&
			    !(rhs.exact & AA_USER_EXEC_TYPE)) {
				/* do nothing */
			} else if ((rhs.exact & AA_USER_EXEC_TYPE) &&
				   !(exact & AA_USER_EXEC_TYPE)) {
				allow = (allow & ~AA_USER_EXEC_TYPE) |
					(rhs.allow & AA_USER_EXEC_TYPE);
			} else
				throw 1;
		} else if (filedfa)
			allow |= rhs.allow & AA_USER_EXEC_TYPE;

		if (filedfa && !is_merged_x_consistent(allow & ALL_OTHER_EXEC,
					    rhs.allow & ALL_OTHER_EXEC)) {
			if ((exact & AA_OTHER_EXEC_TYPE) &&
			    !(rhs.exact & AA_OTHER_EXEC_TYPE)) {
				/* do nothing */
			} else if ((rhs.exact & AA_OTHER_EXEC_TYPE) &&
				   !(exact & AA_OTHER_EXEC_TYPE)) {
				allow = (allow & ~AA_OTHER_EXEC_TYPE) |
					(rhs.allow & AA_OTHER_EXEC_TYPE);
			} else
				throw 1;
		} else if (filedfa)
			allow |= rhs.allow & AA_OTHER_EXEC_TYPE;

		if (filedfa)
			allow = (allow | (rhs.allow & ~ALL_AA_EXEC_TYPE));
		else
			allow |= rhs.allow;
		prompt |= rhs.prompt;
		audit |= rhs.audit;
		quiet = (quiet | rhs.quiet);

		/*
		if (exec & AA_USER_EXEC_TYPE &&
		    (exec & AA_USER_EXEC_TYPE) != (allow & AA_USER_EXEC_TYPE))
			throw 1;
		if (exec & AA_OTHER_EXEC_TYPE &&
		    (exec & AA_OTHER_EXEC_TYPE) != (allow & AA_OTHER_EXEC_TYPE))
			throw 1;
		*/
	}


	/* returns true if perm is no longer accept */
	int apply_and_clear_deny(void)
	{
		if (deny) {
			allow &= ~deny;
			exact &= ~deny;
			prompt &= ~deny;
			/* don't change audit or quiet based on clearing
			 * deny at this stage. This was made unique in
			 * accept_perms, and the info about whether
			 * we are auditing or quieting based on the explicit
			 * deny has been discarded and can only be inferred.
			 * But we know it is correct from accept_perms()
			 * audit &= deny;
			 * quiet &= deny;
			 */
			deny = 0;
			return !is_accept();
		}
		return 0;
	}

	bool operator<(perms_t const &rhs)const
	{
		if (allow < rhs.allow)
			return allow < rhs.allow;
		if (deny < rhs.deny)
			return deny < rhs.deny;
		if (prompt < rhs.prompt)
			return prompt < rhs.prompt;
		if (audit < rhs.audit)
			return audit < rhs.audit;
		return quiet < rhs.quiet;
	}

	perm32_t allow, deny, prompt, audit, quiet, exact;
};

int accept_perms(optflags const &opts, NodeVec *state, perms_t &perms,
		 bool filedfa);

/*
 * ProtoState - NodeSet and ancillery information used to create a state
 */
class ProtoState {
public:
	NodeVec *nnodes;
	NodeVec *anodes;

	/* init is used instead of a constructor because ProtoState is used
	 * in a union
	 */
	void init(NodeVec *n, NodeVec *a = NULL)
	{
		nnodes = n;
		anodes = a;
	}

	bool operator<(ProtoState const &rhs)const
	{
		if (nnodes == rhs.nnodes)
			return anodes < rhs.anodes;
		return nnodes < rhs.nnodes;
	}

	unsigned long size(void)
	{
		if (anodes)
			return nnodes->size() + anodes->size();
		return nnodes->size();
	}
};

/* Temporary state structure used when building differential encoding
 * @parents - set of states that have transitions to this state
 * @depth - level in the DAG
 * @state - back reference to state this DAG entry belongs
 * @rel - state that this state is relative to for differential encoding
 */
struct DiffDag {
	Partition parents;
	int depth;
	State *state;
	State *rel;
};

/*
 * State - DFA individual state information
 * label: a unique label to identify the state used for pretty printing
 *        the non-matching state is setup to have label == 0 and
 *        the start state is setup to have label == 1
 * audit: the audit permission mask for the state
 * accept: the accept permissions for the state
 * trans: set of transitions from this state
 * otherwise: the default state for transitions not in @trans
 * partition: Is a temporary work variable used during dfa minimization.
 *           it can be replaced with a map, but that is slower and uses more
 *           memory.
 * proto: Is a temporary work variable used during dfa creation.  It can
 *        be replaced by using the nodemap, but that is slower
 */
class State {
public:
	State(optflags const &opts, int l, ProtoState &n, State *other,
	      bool filedfa):
		label(l), flags(0), idx(0), perms(), trans()
	{
		int error;

		if (other)
			otherwise = other;
		else
			otherwise = this;

		proto = n;

		/* Compute permissions associated with the State. */
		error = accept_perms(opts, n.anodes, perms, filedfa);
		if (error) {
			//cerr << "Failing on accept perms " << error << "\n";
			throw error;
		}
	};

	State *next(transchar c) {
		State *state = this;
		do {
			StateTrans::iterator i = state->trans.find(c);
			if (i != state->trans.end())
				return i->second;

			if (!(state->flags & DiffEncodeFlag))
				return state->otherwise;
			state = state->otherwise;
		} while (state);

		/* never reached */
		assert(0);
		return NULL;
	}

	ostream &dump(ostream &os)
	{
		os << *this << "\n";
		for (StateTrans::iterator i = trans.begin(); i != trans.end(); i++) {
			os << "    " << i->first.c << " -> " << *i->second << "\n";
		}
		return os;
	}

	int diff_weight(State *rel, int max_range, int upper_bound);
	int make_relative(State *rel, int upper_bound);
	void flatten_relative(State *, int upper_bound);

	int apply_and_clear_deny(void) { return perms.apply_and_clear_deny(); }
	void map_perms_to_accept(perm32_t &accept1, perm32_t &accept2,
				 perm32_t &accept3, bool prompt)
	{
		accept1 = perms.allow;
		if (prompt && prompt_compat_mode == PROMPT_COMPAT_DEV)
			accept2 = PACK_AUDIT_CTL(perms.prompt, perms.quiet);
		else
			accept2 = PACK_AUDIT_CTL(perms.audit, perms.quiet);
		accept3 = perms.prompt;
	}

	int label;
	int flags;
	int idx;
	perms_t perms;
	StateTrans trans;
	State *otherwise;

	/* temp storage for State construction */
	union {
		Partition *partition;	/* used during minimization */
		ProtoState proto;	/* used during creation */
		DiffDag *diff;		/* used during diff encoding */
	};
};

class NodeMap: public CacheStats
{
public:
	typedef std::map<ProtoState, State *>::iterator iterator;
	iterator begin() { return cache.begin(); }
	iterator end() { return cache.end(); }

	std::map<ProtoState, State *> cache;

	NodeMap(void): cache() { };
	~NodeMap() override { clear(); };

	unsigned long size(void) const override { return cache.size(); }

	void clear()
	{
		cache.clear();
		CacheStats::clear();
	}

	std::pair<iterator,bool> insert(ProtoState &proto, State *state)
	{
		std::pair<iterator,bool> uniq;
		uniq = cache.insert(std::make_pair(proto, state));
		if (uniq.second == false) {
			dup++;
		} else {
			sum += proto.size();
			if (proto.size() > max)
				max = proto.size();
		}
		return uniq;
	}
};

typedef std::map<const State *, size_t> Renumber_Map;

/* Transitions in the DFA. */
class DFA {
	void dump_node_to_dfa(void);
	State *add_new_state(optflags const &opts, NodeSet *nodes,
			     State *other);
	State *add_new_state(optflags const &opts,NodeSet *anodes,
			     NodeSet *nnodes, State *other);
	void update_state_transitions(optflags const &opts, State *state);
	void process_work_queue(const char *header, optflags const &);
	void dump_diff_chain(ostream &os, std::map<State *, Partition> &relmap,
			     Partition &chain, State *state,
			     unsigned int &count, unsigned int &total,
			     unsigned int &max);

	/* temporary values used during computations */
	NodeVecCache anodes_cache;
	NodeVecCache nnodes_cache;
	NodeMap node_map;
	std::list<State *> work_queue;

public:
	DFA(Node *root, optflags const &flags, bool filedfa);
	virtual ~DFA();

	State *match_len(State *state, const char *str, size_t len);
	State *match_until(State *state, const char *str, const char term);
	State *match(const char *str);

	void remove_unreachable(optflags const &flags);
	bool same_mappings(State *s1, State *s2);
	void minimize(optflags const &flags);
	int apply_and_clear_deny(void);
	void clear_priorities(void);

	void diff_encode(optflags const &flags);
	void undiff_encode(void);
	void dump_diff_encode(ostream &os);

	void dump(ostream &os, Renumber_Map *renum);
	void dump_dot_graph(ostream &os);
	void dump_uniq_perms(const char *s);
	ostream &dump_partition(ostream &os, Partition &p);
	ostream &dump_partitions(ostream &os, const char *description,
				 std::list<Partition *> &partitions);
	std::map<transchar, transchar> equivalence_classes(optflags const &flags);
	void apply_equivalence_classes(std::map<transchar, transchar> &eq);

	void compute_perms_table_ent(State *state, size_t pos,
				     std::vector <aa_perms> &perms_table,
				     bool prompt);
	void compute_perms_table(std::vector <aa_perms> &perms_table,
				 bool prompt);

	unsigned int diffcount;
	int oob_range;
	int max_range;
	int ord_range;
	int upper_bound;
	Node *root;
	State *nonmatching, *start;
	Partition states;
	bool filedfa;
};

void dump_equivalence_classes(ostream &os, std::map<transchar, transchar> &eq);

#endif /* __LIBAA_RE_HFA_H */
