/*
 * AppArmor Conditional Policy Engine
 * 
 * This module implements a dynamic policy evaluation engine that can make
 * runtime decisions based on contextual conditions such as time, user identity,
 * device state, network conditions, and other environmental factors.
 * 
 * Copyright (C) 2024 AppArmor Project
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include "conditional_policy_engine.h"
#include "parser.h"
#include "lib.h"
#include "profile.h"
#include "af_rule.h"
#include "network_microsegmentation.h"
#include "security_enhancements.h"
#include "performance_monitor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <errno.h>
#include <math.h>
#include <regex.h>
#include <json-c/json.h>

/* Global state for the conditional policy engine */
static struct conditional_policy_engine_state {
    struct policy_condition *conditions;
    struct conditional_policy *policies;
    struct condition_context *context;
    struct performance_metrics *perf_metrics;
    pthread_mutex_t engine_mutex;
    int initialized;
    int debug_mode;
} engine_state = {0};

/* Forward declarations */
static int evaluate_condition_expression(struct policy_condition *condition, 
                                       struct condition_context *context);
static int evaluate_condition_node(struct condition_node *node, 
                                 struct condition_context *context);
static int evaluate_time_condition(struct time_condition *tc, 
                                 struct condition_context *context);
static int evaluate_user_condition(struct user_condition *uc, 
                                 struct condition_context *context);
static int evaluate_network_condition(struct network_condition *nc, 
                                    struct condition_context *context);
static int evaluate_device_condition(struct device_condition *dc, 
                                   struct condition_context *context);
static int evaluate_environment_condition(struct environment_condition *ec, 
                                        struct condition_context *context);
static int evaluate_custom_condition(struct custom_condition *cc, 
                                   struct condition_context *context);
static struct condition_context *build_context_from_request(struct zt_policy_request *request);
static void free_condition_node(struct condition_node *node);
static void free_policy_condition(struct policy_condition *condition);
static void free_conditional_policy(struct conditional_policy *policy);
static int parse_condition_expression(const char *expr, struct condition_node **root);
static int validate_condition_syntax(const char *expr);
static void log_condition_evaluation(const char *condition_id, int result, 
                                   struct condition_context *context);

/**
 * Initialize the conditional policy engine
 */
int conditional_policy_engine_init(int debug_mode) {
    if (engine_state.initialized) {
        return 0;
    }

    memset(&engine_state, 0, sizeof(engine_state));
    
    engine_state.debug_mode = debug_mode;
    engine_state.perf_metrics = performance_monitor_create();
    
    if (!engine_state.perf_metrics) {
        PERROR("Failed to create performance metrics for conditional policy engine\n");
        return -1;
    }

    if (pthread_mutex_init(&engine_state.engine_mutex, NULL) != 0) {
        PERROR("Failed to initialize conditional policy engine mutex\n");
        performance_monitor_destroy(engine_state.perf_metrics);
        return -1;
    }

    engine_state.initialized = 1;
    
    if (engine_state.debug_mode) {
        printf("Conditional Policy Engine initialized successfully\n");
    }
    
    return 0;
}

/**
 * Cleanup the conditional policy engine
 */
void conditional_policy_engine_cleanup(void) {
    if (!engine_state.initialized) {
        return;
    }

    pthread_mutex_lock(&engine_state.engine_mutex);
    
    /* Free all conditions */
    struct policy_condition *cond = engine_state.conditions;
    while (cond) {
        struct policy_condition *next = cond->next;
        free_policy_condition(cond);
        cond = next;
    }
    
    /* Free all policies */
    struct conditional_policy *policy = engine_state.policies;
    while (policy) {
        struct conditional_policy *next = policy->next;
        free_conditional_policy(policy);
        policy = next;
    }
    
    /* Free context */
    if (engine_state.context) {
        free(engine_state.context);
    }
    
    /* Free performance metrics */
    if (engine_state.perf_metrics) {
        performance_monitor_destroy(engine_state.perf_metrics);
    }
    
    pthread_mutex_unlock(&engine_state.engine_mutex);
    pthread_mutex_destroy(&engine_state.engine_mutex);
    
    engine_state.initialized = 0;
    
    if (engine_state.debug_mode) {
        printf("Conditional Policy Engine cleaned up\n");
    }
}

/**
 * Add a policy condition to the engine
 */
int conditional_policy_engine_add_condition(struct policy_condition *condition) {
    if (!engine_state.initialized || !condition) {
        return -1;
    }

    pthread_mutex_lock(&engine_state.engine_mutex);
    
    /* Validate condition syntax */
    if (validate_condition_syntax(condition->expression) != 0) {
        pthread_mutex_unlock(&engine_state.engine_mutex);
        return -1;
    }
    
    /* Parse the condition expression */
    if (parse_condition_expression(condition->expression, &condition->root) != 0) {
        pthread_mutex_unlock(&engine_state.engine_mutex);
        return -1;
    }
    
    /* Add to the list */
    condition->next = engine_state.conditions;
    engine_state.conditions = condition;
    
    pthread_mutex_unlock(&engine_state.engine_mutex);
    
    if (engine_state.debug_mode) {
        printf("Added condition: %s\n", condition->id);
    }
    
    return 0;
}

/**
 * Add a conditional policy to the engine
 */
int conditional_policy_engine_add_policy(struct conditional_policy *policy) {
    if (!engine_state.initialized || !policy) {
        return -1;
    }

    pthread_mutex_lock(&engine_state.engine_mutex);
    
    /* Validate that all referenced conditions exist */
    struct policy_condition *cond = engine_state.conditions;
    int found = 0;
    while (cond) {
        if (strcmp(cond->id, policy->condition_id) == 0) {
            found = 1;
            break;
        }
        cond = cond->next;
    }
    
    if (!found) {
        pthread_mutex_unlock(&engine_state.engine_mutex);
        return -1;
    }
    
    /* Add to the list */
    policy->next = engine_state.policies;
    engine_state.policies = policy;
    
    pthread_mutex_unlock(&engine_state.engine_mutex);
    
    if (engine_state.debug_mode) {
        printf("Added conditional policy: %s\n", policy->id);
    }
    
    return 0;
}

/**
 * Evaluate a policy request against all conditional policies
 */
int conditional_policy_engine_evaluate(struct zt_policy_request *request, 
                                     struct zt_policy_response *response) {
    if (!engine_state.initialized || !request || !response) {
        return -1;
    }

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    pthread_mutex_lock(&engine_state.engine_mutex);
    
    /* Build context from request */
    struct condition_context *context = build_context_from_request(request);
    if (!context) {
        pthread_mutex_unlock(&engine_state.engine_mutex);
        return -1;
    }
    
    /* Initialize response */
    memset(response, 0, sizeof(*response));
    response->decision = ZT_DECISION_DENY; /* Default deny */
    response->confidence = 0.0;
    response->reasoning = NULL;
    
    /* Evaluate all conditional policies */
    struct conditional_policy *policy = engine_state.policies;
    int matched_policies = 0;
    double total_confidence = 0.0;
    
    while (policy) {
        /* Find the condition for this policy */
        struct policy_condition *condition = engine_state.conditions;
        while (condition) {
            if (strcmp(condition->id, policy->condition_id) == 0) {
                break;
            }
            condition = condition->next;
        }
        
        if (condition) {
            /* Evaluate the condition */
            int condition_result = evaluate_condition_expression(condition, context);
            
            if (condition_result > 0) {
                /* Condition matched, apply policy */
                matched_policies++;
                
                if (policy->decision == ZT_DECISION_ALLOW) {
                    response->decision = ZT_DECISION_ALLOW;
                }
                
                /* Accumulate confidence */
                total_confidence += condition_result * policy->weight;
                
                /* Set reasoning */
                if (!response->reasoning) {
                    response->reasoning = strdup(policy->reasoning);
                }
                
                if (engine_state.debug_mode) {
                    printf("Policy %s matched with confidence %d\n", 
                           policy->id, condition_result);
                }
            }
        }
        
        policy = policy->next;
    }
    
    /* Calculate final confidence */
    if (matched_policies > 0) {
        response->confidence = total_confidence / matched_policies;
    }
    
    /* Free context */
    if (context) {
        free(context->profile_name);
        free(context->resource);
        free(context->session_id);
        free(context->source_ip);
        free(context->interface);
        free(context->device_type);
        free(context->device_model);
        free(context->os_version);
        free(context->location);
        free(context->working_directory);
        free(context->hostname);
        free(context->domain);
        free(context->timezone);
        free(context->username);
        free(context->groupname);
        free(context);
    }
    
    pthread_mutex_unlock(&engine_state.engine_mutex);
    
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    
    /* Update performance metrics */
    long elapsed_ns = (end_time.tv_sec - start_time.tv_sec) * 1000000000L + 
                      (end_time.tv_nsec - start_time.tv_nsec);
    performance_monitor_record_function_time(engine_state.perf_metrics, 
                                           "conditional_policy_evaluation", 
                                           elapsed_ns);
    
    if (engine_state.debug_mode) {
        printf("Policy evaluation completed: decision=%d, confidence=%.2f, "
               "matched_policies=%d, elapsed=%ld ns\n", 
               response->decision, response->confidence, matched_policies, elapsed_ns);
    }
    
    return 0;
}

/**
 * Get engine statistics
 */
int conditional_policy_engine_get_stats(struct conditional_engine_stats *stats) {
    if (!engine_state.initialized || !stats) {
        return -1;
    }

    pthread_mutex_lock(&engine_state.engine_mutex);
    
    memset(stats, 0, sizeof(*stats));
    
    /* Count conditions */
    struct policy_condition *cond = engine_state.conditions;
    while (cond) {
        stats->total_conditions++;
        cond = cond->next;
    }
    
    /* Count policies */
    struct conditional_policy *policy = engine_state.policies;
    while (policy) {
        stats->total_policies++;
        policy = policy->next;
    }
    
    /* Get performance metrics */
    if (engine_state.perf_metrics) {
        performance_monitor_get_stats(engine_state.perf_metrics, &stats->perf_stats);
    }
    
    pthread_mutex_unlock(&engine_state.engine_mutex);
    
    return 0;
}

/**
 * Evaluate a condition expression
 */
static int evaluate_condition_expression(struct policy_condition *condition, 
                                       struct condition_context *context) {
    if (!condition || !condition->root || !context) {
        return 0;
    }

    int result = evaluate_condition_node(condition->root, context);
    
    log_condition_evaluation(condition->id, result, context);
    
    return result;
}

/**
 * Evaluate a condition node (recursive)
 */
static int evaluate_condition_node(struct condition_node *node, 
                                 struct condition_context *context) {
    if (!node || !context) {
        return 0;
    }

    switch (node->type) {
        case CONDITION_NODE_LEAF:
            return evaluate_condition_node(node->left, context);
            
        case CONDITION_NODE_AND:
            return evaluate_condition_node(node->left, context) && 
                   evaluate_condition_node(node->right, context);
                   
        case CONDITION_NODE_OR:
            return evaluate_condition_node(node->left, context) || 
                   evaluate_condition_node(node->right, context);
                   
        case CONDITION_NODE_NOT:
            return !evaluate_condition_node(node->left, context);
            
        case CONDITION_NODE_TIME:
            return evaluate_time_condition(&node->time_cond, context);
            
        case CONDITION_NODE_USER:
            return evaluate_user_condition(&node->user_cond, context);
            
        case CONDITION_NODE_NETWORK:
            return evaluate_network_condition(&node->network_cond, context);
            
        case CONDITION_NODE_DEVICE:
            return evaluate_device_condition(&node->device_cond, context);
            
        case CONDITION_NODE_ENVIRONMENT:
            return evaluate_environment_condition(&node->env_cond, context);
            
        case CONDITION_NODE_CUSTOM:
            return evaluate_custom_condition(&node->custom_cond, context);
            
        default:
            return 0;
    }
}

/**
 * Evaluate time-based conditions
 */
static int evaluate_time_condition(struct time_condition *tc, 
                                 struct condition_context *context) {
    if (!tc || !context) {
        return 0;
    }

    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    
    switch (tc->type) {
        case TIME_CONDITION_HOUR:
            return (tm_now->tm_hour >= tc->start_hour && 
                    tm_now->tm_hour <= tc->end_hour);
                    
        case TIME_CONDITION_DAY:
            return (tm_now->tm_wday >= tc->start_day && 
                    tm_now->tm_wday <= tc->end_day);
                    
        case TIME_CONDITION_DATE:
            return (now >= tc->start_time && now <= tc->end_time);
            
        case TIME_CONDITION_TIMEZONE:
            return (strcmp(context->timezone, tc->timezone) == 0);
            
        default:
            return 0;
    }
}

/**
 * Evaluate user-based conditions
 */
static int evaluate_user_condition(struct user_condition *uc, 
                                 struct condition_context *context) {
    if (!uc || !context) {
        return 0;
    }

    switch (uc->type) {
        case USER_CONDITION_UID:
            return (context->uid >= uc->min_uid && context->uid <= uc->max_uid);
            
        case USER_CONDITION_GID:
            return (context->gid >= uc->min_gid && context->gid <= uc->max_gid);
            
        case USER_CONDITION_USERNAME:
            return (strcmp(context->username, uc->username) == 0);
            
        case USER_CONDITION_GROUP:
            return (strcmp(context->groupname, uc->groupname) == 0);
            
        case USER_CONDITION_SESSION:
            return (strcmp(context->session_id, uc->session_id) == 0);
            
        default:
            return 0;
    }
}

/**
 * Evaluate network-based conditions
 */
static int evaluate_network_condition(struct network_condition *nc, 
                                    struct condition_context *context) {
    if (!nc || !context) {
        return 0;
    }

    switch (nc->type) {
        case NETWORK_CONDITION_IP:
            return (strcmp(context->source_ip, nc->ip_address) == 0);
            
        case NETWORK_CONDITION_PORT:
            return (context->source_port >= nc->min_port && 
                    context->source_port <= nc->max_port);
                    
        case NETWORK_CONDITION_PROTOCOL:
            return (context->protocol == nc->protocol);
            
        case NETWORK_CONDITION_INTERFACE:
            return (strcmp(context->interface, nc->interface) == 0);
            
        case NETWORK_CONDITION_BANDWIDTH:
            return (context->bandwidth >= nc->min_bandwidth && 
                    context->bandwidth <= nc->max_bandwidth);
                    
        default:
            return 0;
    }
}

/**
 * Evaluate device-based conditions
 */
static int evaluate_device_condition(struct device_condition *dc, 
                                   struct condition_context *context) {
    if (!dc || !context) {
        return 0;
    }

    switch (dc->type) {
        case DEVICE_CONDITION_TYPE:
            return (strcmp(context->device_type, dc->device_type) == 0);
            
        case DEVICE_CONDITION_MODEL:
            return (strcmp(context->device_model, dc->device_model) == 0);
            
        case DEVICE_CONDITION_OS:
            return (strcmp(context->os_version, dc->os_version) == 0);
            
        case DEVICE_CONDITION_SECURITY:
            return (context->security_level >= dc->min_security_level);
            
        case DEVICE_CONDITION_LOCATION:
            return (strcmp(context->location, dc->location) == 0);
            
        default:
            return 0;
    }
}

/**
 * Evaluate environment-based conditions
 */
static int evaluate_environment_condition(struct environment_condition *ec, 
                                        struct condition_context *context) {
    if (!ec || !context) {
        return 0;
    }

    switch (ec->type) {
        case ENV_CONDITION_VARIABLE:
            return (strcmp(context->env_vars[ec->var_index], ec->value) == 0);
            
        case ENV_CONDITION_PATH:
            return (strcmp(context->working_directory, ec->path) == 0);
            
        case ENV_CONDITION_HOSTNAME:
            return (strcmp(context->hostname, ec->hostname) == 0);
            
        case ENV_CONDITION_DOMAIN:
            return (strcmp(context->domain, ec->domain) == 0);
            
        default:
            return 0;
    }
}

/**
 * Evaluate custom conditions
 */
static int evaluate_custom_condition(struct custom_condition *cc, 
                                   struct condition_context *context) {
    if (!cc || !context) {
        return 0;
    }

    /* This would typically call out to a custom evaluation function */
    /* For now, we'll implement a simple script-based evaluation */
    
    if (cc->evaluation_function) {
        return cc->evaluation_function(cc->parameters, context);
    }
    
    return 0;
}

/**
 * Build context from policy request
 */
static struct condition_context *build_context_from_request(struct zt_policy_request *request) {
    if (!request) {
        return NULL;
    }

    struct condition_context *context = calloc(1, sizeof(*context));
    if (!context) {
        return NULL;
    }

    /* Copy basic request information */
    context->request_id = request->request_id;
    context->profile_name = strdup(request->profile_name);
    context->operation = request->operation;
    context->resource = strdup(request->resource);
    context->uid = request->uid;
    context->gid = request->gid;
    context->pid = request->pid;
    context->ppid = request->ppid;
    context->session_id = strdup(request->session_id);
    context->source_ip = strdup(request->source_ip);
    context->source_port = request->source_port;
    context->protocol = request->protocol;
    context->interface = strdup(request->interface);
    context->bandwidth = request->bandwidth;
    context->device_type = strdup(request->device_type);
    context->device_model = strdup(request->device_model);
    context->os_version = strdup(request->os_version);
    context->security_level = request->security_level;
    context->location = strdup(request->location);
    context->working_directory = strdup(request->working_directory);
    context->hostname = strdup(request->hostname);
    context->domain = strdup(request->domain);
    context->timezone = strdup(request->timezone);
    
    /* Get user information */
    struct passwd *pw = getpwuid(request->uid);
    if (pw) {
        context->username = strdup(pw->pw_name);
    }
    
    struct group *gr = getgrgid(request->gid);
    if (gr) {
        context->groupname = strdup(gr->gr_name);
    }
    
    /* Get system information */
    struct utsname uts;
    if (uname(&uts) == 0) {
        context->hostname = strdup(uts.nodename);
    }
    
    /* Get current time */
    context->timestamp = time(NULL);
    
    return context;
}

/**
 * Free a condition node
 */
static void free_condition_node(struct condition_node *node) {
    if (!node) {
        return;
    }

    if (node->left) {
        free_condition_node(node->left);
    }
    
    if (node->right) {
        free_condition_node(node->right);
    }
    
    free(node);
}

/**
 * Free a policy condition
 */
static void free_policy_condition(struct policy_condition *condition) {
    if (!condition) {
        return;
    }

    if (condition->id) {
        free(condition->id);
    }
    
    if (condition->expression) {
        free(condition->expression);
    }
    
    if (condition->root) {
        free_condition_node(condition->root);
    }
    
    free(condition);
}

/**
 * Free a conditional policy
 */
static void free_conditional_policy(struct conditional_policy *policy) {
    if (!policy) {
        return;
    }

    if (policy->id) {
        free(policy->id);
    }
    
    if (policy->condition_id) {
        free(policy->condition_id);
    }
    
    if (policy->reasoning) {
        free(policy->reasoning);
    }
    
    free(policy);
}

/**
 * Parse a condition expression into an AST
 */
static int parse_condition_expression(const char *expr, struct condition_node **root) {
    if (!expr || !root) {
        return -1;
    }

    /* This is a simplified parser - in a real implementation, you would use
     * a proper expression parser like yacc/bison or a recursive descent parser */
    
    /* For now, we'll create a simple leaf node */
    *root = calloc(1, sizeof(**root));
    if (!*root) {
        return -1;
    }
    
    (*root)->type = CONDITION_NODE_LEAF;
    
    /* Parse the expression and build the AST */
    /* This is a placeholder - real implementation would parse the expression */
    
    return 0;
}

/**
 * Validate condition syntax
 */
static int validate_condition_syntax(const char *expr) {
    if (!expr) {
        return -1;
    }

    /* Basic syntax validation */
    int paren_count = 0;
    int len = strlen(expr);
    
    for (int i = 0; i < len; i++) {
        if (expr[i] == '(') {
            paren_count++;
        } else if (expr[i] == ')') {
            paren_count--;
            if (paren_count < 0) {
                return -1; /* Unmatched closing parenthesis */
            }
        }
    }
    
    if (paren_count != 0) {
        return -1; /* Unmatched opening parenthesis */
    }
    
    return 0;
}

/**
 * Log condition evaluation
 */
static void log_condition_evaluation(const char *condition_id, int result, 
                                   struct condition_context *context) {
    if (!engine_state.debug_mode) {
        return;
    }

    printf("Condition %s evaluated to %s (context: uid=%d, pid=%d, resource=%s)\n",
           condition_id, result ? "TRUE" : "FALSE", 
           context->uid, context->pid, context->resource);
}
