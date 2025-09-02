/*
 * Zero Trust Agent Interface for AppArmor Parser
 * 
 * Provides the interface for the external dynamic policy daemon
 * that makes runtime policy decisions based on external context.
 */

#ifndef ZERO_TRUST_AGENT_H
#define ZERO_TRUST_AGENT_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Agent communication protocol version */
#define ZT_AGENT_PROTOCOL_VERSION 1

/* Message types */
typedef enum {
    ZT_MSG_POLICY_DECISION = 0,
    ZT_MSG_CONTEXT_UPDATE,
    ZT_MSG_RULE_QUERY,
    ZT_MSG_HEALTH_CHECK,
    ZT_MSG_CONFIG_UPDATE,
    ZT_MSG_AUDIT_LOG,
    ZT_MSG_ERROR,
    ZT_MSG_HEARTBEAT
} zt_message_type_t;

/* Decision types */
typedef enum {
    ZT_DECISION_ALLOW = 0,
    ZT_DECISION_DENY,
    ZT_DECISION_AUDIT,
    ZT_DECISION_PROMPT,
    ZT_DECISION_QUARANTINE,
    ZT_DECISION_ESCALATE
} zt_decision_type_t;

/* Context types */
typedef enum {
    ZT_CONTEXT_USER = 0,
    ZT_CONTEXT_DEVICE,
    ZT_CONTEXT_NETWORK,
    ZT_CONTEXT_APPLICATION,
    ZT_CONTEXT_TIME,
    ZT_CONTEXT_LOCATION,
    ZT_CONTEXT_RISK
} zt_context_type_t;

/* Policy decision request */
typedef struct {
    char *request_id;
    char *profile_name;
    char *resource_path;
    uint32_t requested_permissions;
    char *user_id;
    char *process_id;
    char *session_id;
    char *device_id;
    char *ip_address;
    char *user_agent;
    time_t timestamp;
    void *additional_context;
} zt_decision_request_t;

/* Policy decision response */
typedef struct {
    char *request_id;
    zt_decision_type_t decision;
    char *reason;
    uint32_t confidence;
    uint32_t cache_ttl_seconds;
    char *escalation_path;
    void *additional_data;
    time_t timestamp;
} zt_decision_response_t;

/* Context update */
typedef struct {
    zt_context_type_t type;
    char *entity_id;
    char *attribute_name;
    char *attribute_value;
    time_t timestamp;
    uint32_t ttl_seconds;
} zt_context_update_t;

/* Agent configuration */
typedef struct {
    char *agent_name;
    char *version;
    char *endpoint_url;
    char *api_key;
    char *certificate_path;
    char *private_key_path;
    uint32_t timeout_ms;
    uint32_t retry_count;
    uint32_t heartbeat_interval_ms;
    bool enable_encryption;
    bool enable_compression;
    char *log_level;
    char *log_file;
} zt_agent_config_t;

/* Agent statistics */
typedef struct {
    uint64_t total_requests;
    uint64_t allowed_requests;
    uint64_t denied_requests;
    uint64_t cached_requests;
    uint64_t failed_requests;
    uint64_t total_response_time_ms;
    uint64_t avg_response_time_ms;
    uint64_t max_response_time_ms;
    time_t last_request_time;
    time_t last_response_time;
    bool is_connected;
    uint32_t connection_errors;
} zt_agent_stats_t;

/* Function prototypes */
int zt_agent_init(const zt_agent_config_t *config);
void zt_agent_cleanup(void);
int zt_agent_start(void);
int zt_agent_stop(void);
bool zt_agent_is_running(void);

/* Policy decision functions */
int zt_agent_request_decision(const zt_decision_request_t *request,
                             zt_decision_response_t **response);
int zt_agent_request_decision_async(const zt_decision_request_t *request,
                                   void (*callback)(const zt_decision_response_t *response, void *user_data),
                                   void *user_data);

/* Context management */
int zt_agent_update_context(const zt_context_update_t *update);
int zt_agent_get_context(zt_context_type_t type, const char *entity_id, char **value);
int zt_agent_clear_context(zt_context_type_t type, const char *entity_id);

/* Cache management */
int zt_agent_cache_put(const char *key, const void *data, size_t size, uint32_t ttl_seconds);
int zt_agent_cache_get(const char *key, void **data, size_t *size);
int zt_agent_cache_remove(const char *key);
int zt_agent_cache_clear(void);

/* Configuration management */
int zt_agent_reload_config(const zt_agent_config_t *config);
int zt_agent_get_config(zt_agent_config_t **config);
int zt_agent_validate_config(const zt_agent_config_t *config);

/* Statistics and monitoring */
zt_agent_stats_t *zt_agent_get_stats(void);
void zt_agent_print_stats(const zt_agent_stats_t *stats);
void zt_agent_reset_stats(void);

/* Health check */
int zt_agent_health_check(void);
bool zt_agent_is_healthy(void);

/* Logging */
int zt_agent_set_log_level(const char *level);
int zt_agent_set_log_file(const char *filename);
int zt_agent_log_message(const char *level, const char *message);

/* External system integration */
typedef struct {
    char *system_name;
    char *endpoint_url;
    char *api_key;
    uint32_t timeout_ms;
    bool enable_ssl;
    char *certificate_path;
} zt_external_system_t;

int zt_agent_register_external_system(const zt_external_system_t *system);
int zt_agent_unregister_external_system(const char *system_name);
int zt_agent_query_external_system(const char *system_name,
                                  const char *query,
                                  char **response);

/* Plugin system */
typedef struct {
    char *plugin_name;
    char *version;
    int (*init)(void);
    int (*cleanup)(void);
    int (*process_request)(const zt_decision_request_t *request,
                          zt_decision_response_t **response);
    int (*update_context)(const zt_context_update_t *update);
} zt_agent_plugin_t;

int zt_agent_register_plugin(const zt_agent_plugin_t *plugin);
int zt_agent_unregister_plugin(const char *plugin_name);

/* Built-in plugins */
int zt_agent_plugin_identity_init(void);
int zt_agent_plugin_time_init(void);
int zt_agent_plugin_location_init(void);
int zt_agent_plugin_risk_init(void);

/* Utility functions */
const char *zt_message_type_to_string(zt_message_type_t type);
const char *zt_decision_type_to_string(zt_decision_type_t decision);
const char *zt_context_type_to_string(zt_context_type_t type);
void zt_agent_print_config(const zt_agent_config_t *config);

/* Error handling */
typedef enum {
    ZT_AGENT_SUCCESS = 0,
    ZT_AGENT_ERROR_INVALID_CONFIG,
    ZT_AGENT_ERROR_CONNECTION_FAILED,
    ZT_AGENT_ERROR_TIMEOUT,
    ZT_AGENT_ERROR_AUTHENTICATION_FAILED,
    ZT_AGENT_ERROR_INVALID_REQUEST,
    ZT_AGENT_ERROR_INVALID_RESPONSE,
    ZT_AGENT_ERROR_CACHE_ERROR,
    ZT_AGENT_ERROR_PLUGIN_ERROR,
    ZT_AGENT_ERROR_MEMORY_ALLOCATION
} zt_agent_error_t;

const char *zt_agent_error_to_string(zt_agent_error_t error);

/* Default configuration */
zt_agent_config_t *zt_agent_default_config(void);

/* Example configurations */
#define ZT_AGENT_CONFIG_EXAMPLE_LOCAL \
    { \
        .agent_name = "local-zt-agent", \
        .version = "1.0.0", \
        .endpoint_url = "http://localhost:8080/api/v1", \
        .timeout_ms = 5000, \
        .retry_count = 3, \
        .heartbeat_interval_ms = 30000, \
        .enable_encryption = false, \
        .enable_compression = true, \
        .log_level = "INFO" \
    }

#define ZT_AGENT_CONFIG_EXAMPLE_CLOUD \
    { \
        .agent_name = "cloud-zt-agent", \
        .version = "1.0.0", \
        .endpoint_url = "https://api.zt-cloud.com/v1", \
        .timeout_ms = 10000, \
        .retry_count = 5, \
        .heartbeat_interval_ms = 60000, \
        .enable_encryption = true, \
        .enable_compression = true, \
        .log_level = "DEBUG" \
    }

#ifdef __cplusplus
}
#endif

#endif /* ZERO_TRUST_AGENT_H */
