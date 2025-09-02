/*
 * Conditional Policy Engine for AppArmor Parser
 * 
 * Provides support for conditional policies that are evaluated
 * at access time based on external context.
 */

#ifndef CONDITIONAL_POLICY_ENGINE_H
#define CONDITIONAL_POLICY_ENGINE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Condition types */
typedef enum {
    CONDITION_TYPE_IDENTITY = 0,
    CONDITION_TYPE_AUTH_STRENGTH,
    CONDITION_TYPE_TIME,
    CONDITION_TYPE_LOCATION,
    CONDITION_TYPE_DEVICE_HEALTH,
    CONDITION_TYPE_NETWORK_ZONE,
    CONDITION_TYPE_USER_ATTRIBUTE,
    CONDITION_TYPE_GROUP_MEMBERSHIP,
    CONDITION_TYPE_CERTIFICATE,
    CONDITION_TYPE_RISK_SCORE,
    CONDITION_TYPE_CUSTOM
} condition_type_t;

/* Condition operators */
typedef enum {
    CONDITION_OP_EQUALS = 0,
    CONDITION_OP_NOT_EQUALS,
    CONDITION_OP_CONTAINS,
    CONDITION_OP_STARTS_WITH,
    CONDITION_OP_ENDS_WITH,
    CONDITION_OP_REGEX,
    CONDITION_OP_GREATER_THAN,
    CONDITION_OP_LESS_THAN,
    CONDITION_OP_GREATER_EQUAL,
    CONDITION_OP_LESS_EQUAL,
    CONDITION_OP_IN_RANGE,
    CONDITION_OP_EXISTS,
    CONDITION_OP_NOT_EXISTS
} condition_operator_t;

/* Logical operators */
typedef enum {
    LOGICAL_OP_AND = 0,
    LOGICAL_OP_OR,
    LOGICAL_OP_NOT,
    LOGICAL_OP_XOR
} logical_operator_t;

/* Condition structure */
typedef struct {
    condition_type_t type;
    condition_operator_t op;
    char *attribute;        /* Attribute name (e.g., "user", "group") */
    char *value;           /* Expected value */
    char *regex_pattern;   /* For regex operations */
    struct {
        char *min_value;
        char *max_value;
    } range;              /* For range operations */
    bool case_sensitive;
    uint32_t timeout_ms;   /* Evaluation timeout */
} condition_t;

/* Condition node for expression tree */
typedef struct condition_node {
    union {
        condition_t condition;
        logical_operator_t logical_op;
    } data;
    bool is_condition;     /* true if this is a condition, false if logical op */
    struct condition_node *left;
    struct condition_node *right;
    struct condition_node *parent;
} condition_node_t;

/* Conditional rule */
typedef struct {
    char *rule_id;
    condition_node_t *condition_tree;
    char *action;          /* "allow", "deny", "audit", "prompt" */
    char *target;          /* Target resource */
    uint32_t permissions;  /* Permissions to grant/deny */
    bool audit;
    bool deny;
    uint32_t priority;     /* Rule priority (higher = more important) */
    time_t created;
    time_t expires;        /* Rule expiration time (0 = never) */
} conditional_rule_t;

/* Conditional rule list */
typedef struct conditional_rule_node {
    conditional_rule_t rule;
    struct conditional_rule_node *next;
} conditional_rule_node_t;

typedef struct {
    conditional_rule_node_t *head;
    conditional_rule_node_t *tail;
    size_t count;
} conditional_rule_list_t;

/* Context for condition evaluation */
typedef struct {
    char *user_id;
    char *user_name;
    char *group_id;
    char *group_name;
    char *session_id;
    char *device_id;
    char *ip_address;
    char *location;
    char *timezone;
    time_t current_time;
    uint32_t auth_strength;
    uint32_t risk_score;
    char *certificate_hash;
    char *network_zone;
    char *device_health_status;
    void *custom_attributes;  /* Custom attribute map */
} evaluation_context_t;

/* Evaluation result */
typedef struct {
    bool result;           /* true = condition met, false = condition not met */
    char *reason;          /* Human-readable reason for the result */
    uint32_t confidence;   /* Confidence level (0-100) */
    time_t evaluated_at;
    uint32_t evaluation_time_ms;
} evaluation_result_t;

/* External condition provider interface */
typedef struct {
    char *name;
    char *version;
    int (*evaluate_condition)(const condition_t *condition,
                             const evaluation_context_t *context,
                             evaluation_result_t *result);
    int (*validate_condition)(const condition_t *condition);
    void (*cleanup)(void);
} condition_provider_t;

/* Function prototypes */
conditional_rule_list_t *conditional_rules_create(void);
void conditional_rules_destroy(conditional_rule_list_t *rules);
int conditional_rules_add(conditional_rule_list_t *rules, const conditional_rule_t *rule);
int conditional_rules_remove(conditional_rule_list_t *rules, const char *rule_id);
conditional_rule_t *conditional_rules_find(conditional_rule_list_t *rules, const char *rule_id);

/* Condition parsing */
int condition_parse(const char *condition_str, condition_node_t **condition_tree);
void condition_destroy_tree(condition_node_t *tree);
int condition_validate_tree(const condition_node_t *tree);

/* Condition evaluation */
int condition_evaluate_tree(const condition_node_t *tree,
                           const evaluation_context_t *context,
                           evaluation_result_t *result);
int condition_evaluate(const condition_t *condition,
                      const evaluation_context_t *context,
                      evaluation_result_t *result);

/* Context management */
evaluation_context_t *evaluation_context_create(void);
void evaluation_context_destroy(evaluation_context_t *context);
int evaluation_context_set_attribute(evaluation_context_t *context,
                                    const char *name,
                                    const char *value);
const char *evaluation_context_get_attribute(const evaluation_context_t *context,
                                           const char *name);

/* Rule evaluation */
int conditional_rules_evaluate(conditional_rule_list_t *rules,
                              const evaluation_context_t *context,
                              const char *target,
                              uint32_t requested_permissions,
                              evaluation_result_t *result);

/* Provider management */
int condition_provider_register(const condition_provider_t *provider);
int condition_provider_unregister(const char *provider_name);
condition_provider_t *condition_provider_find(const char *provider_name);

/* Built-in condition providers */
int condition_provider_identity_init(void);
int condition_provider_time_init(void);
int condition_provider_location_init(void);
int condition_provider_auth_init(void);

/* Rule compilation */
int conditional_rules_compile(conditional_rule_list_t *rules,
                             void **binary_data,
                             size_t *binary_size);
int conditional_rules_decompile(const void *binary_data,
                               size_t binary_size,
                               conditional_rule_list_t **rules);

/* Rule optimization */
int conditional_rules_optimize(conditional_rule_list_t *rules);
int conditional_rules_merge(conditional_rule_list_t *rules);
int conditional_rules_validate(conditional_rule_list_t *rules);

/* Statistics and monitoring */
typedef struct {
    uint64_t total_rules;
    uint64_t active_rules;
    uint64_t evaluated_rules;
    uint64_t matched_rules;
    uint64_t denied_rules;
    uint64_t evaluation_time_total_ms;
    uint64_t evaluation_time_avg_ms;
    uint64_t evaluation_time_max_ms;
    double match_rate;
    double deny_rate;
} conditional_rule_stats_t;

conditional_rule_stats_t *conditional_rules_get_stats(conditional_rule_list_t *rules);
void conditional_rules_print_stats(const conditional_rule_stats_t *stats);

/* Utility functions */
const char *condition_type_to_string(condition_type_t type);
const char *condition_operator_to_string(condition_operator_t op);
const char *logical_operator_to_string(logical_operator_t op);
void condition_print_tree(const condition_node_t *tree, int indent);

/* Error handling */
typedef enum {
    CONDITION_SUCCESS = 0,
    CONDITION_ERROR_INVALID_SYNTAX,
    CONDITION_ERROR_UNKNOWN_ATTRIBUTE,
    CONDITION_ERROR_UNKNOWN_OPERATOR,
    CONDITION_ERROR_EVALUATION_FAILED,
    CONDITION_ERROR_TIMEOUT,
    CONDITION_ERROR_PROVIDER_NOT_FOUND,
    CONDITION_ERROR_INVALID_CONTEXT,
    CONDITION_ERROR_MEMORY_ALLOCATION
} condition_error_t;

const char *condition_error_to_string(condition_error_t error);

/* Example condition strings */
#define CONDITION_EXAMPLE_IDENTITY "identity:user@corp.com"
#define CONDITION_EXAMPLE_AUTH "auth_strength:mfa"
#define CONDITION_EXAMPLE_TIME "time:09:00-17:00"
#define CONDITION_EXAMPLE_LOCATION "location:office"
#define CONDITION_EXAMPLE_COMPLEX "(identity:user@corp.com && auth_strength:mfa) || (time:09:00-17:00 && location:office)"

#ifdef __cplusplus
}
#endif

#endif /* CONDITIONAL_POLICY_ENGINE_H */
