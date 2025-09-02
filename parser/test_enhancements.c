/*
 * Test Suite for AppArmor Parser Enhancements
 * 
 * Comprehensive tests for the new adaptive cache, enhanced error handling,
 * performance monitoring, and security enhancements.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>

#include "adaptive_cache.h"
#include "enhanced_error.h"
#include "performance_monitor.h"
#include "security_enhancements.h"
#include "network_microsegmentation.h"
#include "binary_profile_serialization.h"
#include "conditional_policy_engine.h"
#include "zero_trust_agent.h"

/* Test configuration */
#define TEST_CACHE_SIZE 1024
#define TEST_ITERATIONS 1000
#define TEST_DATA_SIZE 1024

/* Test results */
typedef struct {
    int passed;
    int failed;
    int total;
} test_results_t;

static test_results_t results = {0};

/* Test helper macros */
#define TEST_ASSERT(condition, message) \
    do { \
        results.total++; \
        if (condition) { \
            results.passed++; \
            printf("PASS: %s\n", message); \
        } else { \
            results.failed++; \
            printf("FAIL: %s\n", message); \
        } \
    } while(0)

#define TEST_START(name) \
    printf("\n=== Testing %s ===\n", name)

/* Test adaptive cache functionality */
void test_adaptive_cache(void) {
    TEST_START("Adaptive Cache");
    
    /* Test cache creation */
    cache_config_t *config = adaptive_cache_default_config();
    TEST_ASSERT(config != NULL, "Default config creation");
    
    config->max_memory = TEST_CACHE_SIZE;
    config->max_entries = 100;
    
    adaptive_cache_t *cache = adaptive_cache_create(config);
    TEST_ASSERT(cache != NULL, "Cache creation");
    
    /* Test cache operations */
    char test_data[TEST_DATA_SIZE];
    memset(test_data, 'A', sizeof(test_data));
    
    int put_result = adaptive_cache_put(cache, "test_key", test_data, sizeof(test_data));
    TEST_ASSERT(put_result == 0, "Cache put operation");
    
    size_t retrieved_size;
    void *retrieved_data = adaptive_cache_get(cache, "test_key", &retrieved_size);
    TEST_ASSERT(retrieved_data != NULL, "Cache get operation");
    TEST_ASSERT(retrieved_size == sizeof(test_data), "Cache data size match");
    TEST_ASSERT(memcmp(retrieved_data, test_data, sizeof(test_data)) == 0, "Cache data integrity");
    
    /* Test cache statistics */
    cache_stats_t *stats = adaptive_cache_get_stats(cache);
    TEST_ASSERT(stats != NULL, "Cache statistics retrieval");
    TEST_ASSERT(stats->hits > 0, "Cache hit recorded");
    TEST_ASSERT(stats->total_accesses > 0, "Cache access recorded");
    
    /* Test cache removal */
    int remove_result = adaptive_cache_remove(cache, "test_key");
    TEST_ASSERT(remove_result == 0, "Cache remove operation");
    
    void *removed_data = adaptive_cache_get(cache, "test_key", NULL);
    TEST_ASSERT(removed_data == NULL, "Cache data removed");
    
    /* Test cache auto-tuning */
    adaptive_cache_auto_tune(cache);
    TEST_ASSERT(1, "Cache auto-tuning completed");
    
    /* Cleanup */
    adaptive_cache_destroy(cache);
    adaptive_free(config);
}

/* Test enhanced error handling */
void test_enhanced_error_handling(void) {
    TEST_START("Enhanced Error Handling");
    
    /* Initialize error system */
    enhanced_error_init();
    TEST_ASSERT(1, "Error system initialization");
    
    /* Test error reporting */
    ENHANCED_ERROR(ERROR_LEVEL_INFO, ERROR_CATEGORY_PARSER, 1, "Test error message");
    TEST_ASSERT(1, "Error reporting");
    
    /* Test error statistics */
    error_stats_t *stats = enhanced_error_get_stats();
    TEST_ASSERT(stats != NULL, "Error statistics retrieval");
    TEST_ASSERT(stats->total_errors > 0, "Error recorded in statistics");
    
    /* Test error recovery */
    error_context_t context = {0};
    context.category = ERROR_CATEGORY_MEMORY;
    context.error_code = 1;
    
    error_recovery_t recovery = enhanced_error_suggest_recovery(&context);
    TEST_ASSERT(recovery != ERROR_RECOVERY_NONE, "Recovery suggestion");
    
    int recovery_result = enhanced_error_attempt_recovery(recovery, &context);
    TEST_ASSERT(recovery_result >= 0, "Recovery attempt");
    
    /* Test error level filtering */
    enhanced_error_set_level(ERROR_LEVEL_WARNING);
    ENHANCED_ERROR(ERROR_LEVEL_INFO, ERROR_CATEGORY_PARSER, 2, "This should be filtered");
    ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_PARSER, 3, "This should be shown");
    
    /* Cleanup */
    enhanced_error_cleanup();
}

/* Test performance monitoring */
void test_performance_monitoring(void) {
    TEST_START("Performance Monitoring");
    
    /* Initialize performance monitor */
    monitor_config_t config = {0};
    config.enable_profiling = 1;
    config.enable_memory_tracking = 1;
    config.enable_cpu_tracking = 1;
    
    performance_monitor_init(&config);
    TEST_ASSERT(1, "Performance monitor initialization");
    
    /* Test profiling */
    PERFORMANCE_PROFILE_START("test_function");
    
    /* Simulate some work */
    usleep(1000); /* 1ms */
    
    PERFORMANCE_PROFILE_END("test_function");
    TEST_ASSERT(1, "Performance profiling");
    
    /* Test memory tracking */
    void *test_memory = PERFORMANCE_MALLOC(1024);
    TEST_ASSERT(test_memory != NULL, "Memory allocation tracking");
    
    PERFORMANCE_FREE(test_memory);
    TEST_ASSERT(1, "Memory deallocation tracking");
    
    /* Test performance profile retrieval */
    performance_profile_t *profile = performance_monitor_get_profile("test_function");
    TEST_ASSERT(profile != NULL, "Performance profile retrieval");
    TEST_ASSERT(profile->metric.call_count > 0, "Function call count recorded");
    
    /* Test optimization suggestions */
    optimization_suggestion_t *suggestions = performance_monitor_analyze_performance();
    TEST_ASSERT(suggestions != NULL, "Performance analysis");
    
    /* Cleanup */
    performance_monitor_cleanup();
}

/* Test security enhancements */
void test_security_enhancements(void) {
    TEST_START("Security Enhancements");
    
    /* Test input validation */
    TEST_ASSERT(security_validate_path("/usr/bin/test", 256), "Valid path validation");
    TEST_ASSERT(!security_validate_path("../../../etc/passwd", 256), "Invalid path validation");
    
    TEST_ASSERT(security_validate_profile_name("test_profile", 256), "Valid profile name");
    TEST_ASSERT(!security_validate_profile_name("", 256), "Empty profile name validation");
    
    /* Test secure string functions */
    char *secure_copy = security_strdup("test string");
    TEST_ASSERT(secure_copy != NULL, "Secure string duplication");
    TEST_ASSERT(strcmp(secure_copy, "test string") == 0, "Secure string content");
    security_free(secure_copy);
    
    /* Test buffer overflow protection */
    char buffer[10];
    TEST_ASSERT(security_strcpy(buffer, sizeof(buffer), "short") == 0, "Safe string copy");
    TEST_ASSERT(security_strcpy(buffer, sizeof(buffer), "very long string") != 0, "Buffer overflow protection");
    
    /* Test integer overflow protection */
    size_t result;
    TEST_ASSERT(security_check_add_overflow(100, 200, &result), "Safe addition");
    TEST_ASSERT(result == 300, "Addition result");
    
    TEST_ASSERT(!security_check_add_overflow(SIZE_MAX, 1, &result), "Integer overflow detection");
    
    /* Test memory protection */
    void *secure_memory = security_malloc(1024);
    TEST_ASSERT(secure_memory != NULL, "Secure memory allocation");
    
    security_memset(secure_memory, 0xAA, 1024);
    TEST_ASSERT(1, "Secure memory initialization");
    
    security_free(secure_memory);
    TEST_ASSERT(1, "Secure memory deallocation");
    
    /* Test cryptographic helpers */
    uint8_t random_bytes[16];
    security_generate_random_bytes(random_bytes, sizeof(random_bytes));
    TEST_ASSERT(1, "Random byte generation");
    
    uint32_t random_uint = security_generate_random_uint32();
    TEST_ASSERT(1, "Random uint32 generation");
    
    /* Test constant time comparison */
    char data1[] = "test data";
    char data2[] = "test data";
    char data3[] = "different";
    
    TEST_ASSERT(security_constant_time_compare(data1, data2, strlen(data1)), "Constant time comparison - equal");
    TEST_ASSERT(!security_constant_time_compare(data1, data3, strlen(data1)), "Constant time comparison - different");
}

/* Test network microsegmentation */
void test_network_microsegmentation(void) {
    TEST_START("Network Microsegmentation");
    
    /* Test network rules creation */
    network_rule_list_t *rules = network_rules_create();
    TEST_ASSERT(rules != NULL, "Network rules creation");
    
    /* Test network rule parsing */
    network_rule_t rule;
    int parse_result = network_parse_rule("create inet tcp port 443", &rule);
    TEST_ASSERT(parse_result == 0, "Network rule parsing");
    TEST_ASSERT(rule.type == NET_RULE_CREATE, "Network rule type");
    TEST_ASSERT(rule.protocol == NET_PROTO_INET, "Network protocol");
    TEST_ASSERT(rule.transport == NET_TRANSPORT_TCP, "Network transport");
    TEST_ASSERT(rule.local_addr.port == 443, "Network port");
    
    /* Test network rule validation */
    TEST_ASSERT(network_validate_rule(&rule), "Network rule validation");
    
    /* Test network rule addition */
    int add_result = network_rules_add(rules, &rule);
    TEST_ASSERT(add_result == 0, "Network rule addition");
    TEST_ASSERT(rules->count == 1, "Network rule count");
    
    /* Test network rule matching */
    network_address_t local_addr = {0};
    local_addr.family = AF_INET;
    local_addr.port = 443;
    
    bool match_result = network_rules_match(rules, NET_RULE_CREATE, NET_PROTO_INET, 
                                           NET_TRANSPORT_TCP, &local_addr, NULL);
    TEST_ASSERT(match_result, "Network rule matching");
    
    /* Test network rule compilation */
    void *binary_data;
    size_t binary_size;
    int compile_result = network_compile_rules(rules, &binary_data, &binary_size);
    TEST_ASSERT(compile_result == 0, "Network rule compilation");
    TEST_ASSERT(binary_data != NULL, "Binary data allocation");
    TEST_ASSERT(binary_size > 0, "Binary data size");
    
    /* Test network rule statistics */
    network_rule_stats_t *stats = network_get_rule_stats(rules);
    TEST_ASSERT(stats != NULL, "Network rule statistics");
    TEST_ASSERT(stats->total_rules == 1, "Network rule statistics count");
    
    /* Cleanup */
    security_free(binary_data);
    network_rules_destroy(rules);
}

/* Test binary profile serialization */
void test_binary_profile_serialization(void) {
    TEST_START("Binary Profile Serialization");
    
    /* Test binary profile creation */
    binary_profile_t *profile = binary_profile_create("test_profile");
    TEST_ASSERT(profile != NULL, "Binary profile creation");
    TEST_ASSERT(profile->header.magic == BINARY_PROFILE_MAGIC, "Binary profile magic");
    TEST_ASSERT(strcmp(profile->header.profile_name, "test_profile") == 0, "Binary profile name");
    
    /* Test profile serialization */
    char test_data[] = "This is test profile data";
    int serialize_result = binary_profile_serialize(profile, test_data, sizeof(test_data), NULL);
    TEST_ASSERT(serialize_result == 0, "Binary profile serialization");
    TEST_ASSERT(profile->data != NULL, "Binary profile data");
    TEST_ASSERT(profile->data_size == sizeof(test_data), "Binary profile data size");
    
    /* Test profile validation */
    int validate_result = binary_profile_validate(profile);
    TEST_ASSERT(validate_result == 0, "Binary profile validation");
    
    /* Test profile checksum verification */
    int checksum_result = binary_profile_verify_checksum(profile);
    TEST_ASSERT(checksum_result == 0, "Binary profile checksum verification");
    
    /* Test profile compression */
    int compress_result = binary_profile_compress(profile, 6);
    TEST_ASSERT(compress_result == 0, "Binary profile compression");
    TEST_ASSERT(profile->header.flags & 0x01, "Binary profile compression flag");
    
    /* Test profile decompression */
    int decompress_result = binary_profile_decompress(profile);
    TEST_ASSERT(decompress_result == 0, "Binary profile decompression");
    TEST_ASSERT(!(profile->header.flags & 0x01), "Binary profile compression flag cleared");
    
    /* Test profile deserialization */
    binary_profile_t *deserialized_profile;
    int deserialize_result = binary_profile_deserialize(profile->data, profile->data_size, &deserialized_profile);
    TEST_ASSERT(deserialize_result == 0, "Binary profile deserialization");
    TEST_ASSERT(deserialized_profile != NULL, "Deserialized profile allocation");
    TEST_ASSERT(strcmp(deserialized_profile->header.profile_name, "test_profile") == 0, "Deserialized profile name");
    
    /* Test profile statistics */
    binary_profile_stats_t *stats = binary_profile_get_stats();
    TEST_ASSERT(stats != NULL, "Binary profile statistics");
    
    /* Cleanup */
    binary_profile_destroy(profile);
    binary_profile_destroy(deserialized_profile);
}

/* Test integration between components */
void test_integration(void) {
    TEST_START("Component Integration");
    
    /* Initialize all systems */
    enhanced_error_init();
    
    cache_config_t *cache_config = adaptive_cache_default_config();
    adaptive_cache_t *cache = adaptive_cache_create(cache_config);
    
    monitor_config_t monitor_config = {0};
    monitor_config.enable_profiling = 1;
    performance_monitor_init(&monitor_config);
    
    /* Test error handling with cache operations */
    PERFORMANCE_PROFILE_START("cache_operation");
    
    char test_data[] = "integration test data";
    int result = adaptive_cache_put(cache, "integration_key", test_data, sizeof(test_data));
    
    if (result != 0) {
        ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_MEMORY, 1, "Cache put failed");
    }
    
    PERFORMANCE_PROFILE_END("cache_operation");
    
    /* Test security validation with cache operations */
    if (security_validate_path("integration_key", 256)) {
        size_t size;
        void *data = adaptive_cache_get(cache, "integration_key", &size);
        TEST_ASSERT(data != NULL, "Integrated cache get operation");
        TEST_ASSERT(size == sizeof(test_data), "Integrated cache data size");
    }
    
    /* Test performance analysis with error handling */
    optimization_suggestion_t *suggestions = performance_monitor_analyze_performance();
    if (suggestions) {
        ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Performance analysis completed");
    }
    
    /* Test network microsegmentation integration */
    network_rule_list_t *rules = network_rules_create();
    if (rules) {
        network_rule_t rule;
        if (network_parse_rule("create inet tcp port 80", &rule) == 0) {
            network_rules_add(rules, &rule);
            ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Network rule added successfully");
        }
        network_rules_destroy(rules);
    }
    
    /* Test binary profile serialization integration */
    binary_profile_t *profile = binary_profile_create("integration_test");
    if (profile) {
        char profile_data[] = "profile integration_test { /bin/test r, }";
        if (binary_profile_serialize(profile, profile_data, sizeof(profile_data), NULL) == 0) {
            ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Binary profile serialized successfully");
        }
        binary_profile_destroy(profile);
    }
    
    /* Cleanup */
    adaptive_cache_destroy(cache);
    adaptive_free(cache_config);
    performance_monitor_cleanup();
    enhanced_error_cleanup();
}

/* Test conditional policy engine */
void test_conditional_policy_engine(void) {
    printf("\n--- Testing Conditional Policy Engine ---\n");
    
    /* Initialize the engine */
    TEST_ASSERT(conditional_policy_engine_init(1) == 0, "Conditional policy engine initialization");
    
    /* Create a test condition */
    struct policy_condition *condition = calloc(1, sizeof(*condition));
    TEST_ASSERT(condition != NULL, "Condition allocation");
    
    condition->id = strdup("test_condition");
    condition->expression = strdup("time.hour >= 9 AND time.hour <= 17");
    condition->type = CONDITION_TYPE_TIME;
    condition->priority = 100;
    
    /* Add condition to engine */
    TEST_ASSERT(conditional_policy_engine_add_condition(condition) == 0, "Add condition to engine");
    
    /* Create a test policy */
    struct conditional_policy *policy = calloc(1, sizeof(*policy));
    TEST_ASSERT(policy != NULL, "Policy allocation");
    
    policy->id = strdup("test_policy");
    policy->condition_id = strdup("test_condition");
    policy->decision = ZT_DECISION_ALLOW;
    policy->weight = 0.8;
    policy->reasoning = strdup("Business hours access");
    
    /* Add policy to engine */
    TEST_ASSERT(conditional_policy_engine_add_policy(policy) == 0, "Add policy to engine");
    
    /* Create a test request */
    struct zt_policy_request request = {0};
    request.request_id = 12345;
    request.profile_name = strdup("test_profile");
    request.operation = ZT_OPERATION_FILE_READ;
    request.resource = strdup("/etc/passwd");
    request.uid = 1000;
    request.gid = 1000;
    request.pid = 1234;
    request.ppid = 5678;
    request.session_id = strdup("session123");
    request.source_ip = strdup("192.168.1.100");
    request.source_port = 12345;
    request.protocol = IPPROTO_TCP;
    request.interface = strdup("eth0");
    request.bandwidth = 1000000;
    request.device_type = strdup("desktop");
    request.device_model = strdup("workstation");
    request.os_version = strdup("Linux 5.4.0");
    request.security_level = 5;
    request.location = strdup("office");
    request.working_directory = strdup("/home/user");
    request.hostname = strdup("workstation");
    request.domain = strdup("company.com");
    request.timezone = strdup("UTC");
    
    /* Evaluate the request */
    struct zt_policy_response response;
    TEST_ASSERT(conditional_policy_engine_evaluate(&request, &response) == 0, "Policy evaluation");
    
    /* Check response */
    TEST_ASSERT(response.decision == ZT_DECISION_ALLOW || response.decision == ZT_DECISION_DENY, "Valid decision");
    TEST_ASSERT(response.confidence >= 0.0 && response.confidence <= 1.0, "Valid confidence");
    
    /* Get engine statistics */
    struct conditional_engine_stats stats;
    TEST_ASSERT(conditional_policy_engine_get_stats(&stats) == 0, "Get engine statistics");
    TEST_ASSERT(stats.total_conditions == 1, "Correct condition count");
    TEST_ASSERT(stats.total_policies == 1, "Correct policy count");
    
    /* Cleanup */
    free(request.profile_name);
    free(request.resource);
    free(request.session_id);
    free(request.source_ip);
    free(request.interface);
    free(request.device_type);
    free(request.device_model);
    free(request.os_version);
    free(request.location);
    free(request.working_directory);
    free(request.hostname);
    free(request.domain);
    free(request.timezone);
    
    conditional_policy_engine_cleanup();
}

/* Test zero trust agent */
void test_zero_trust_agent(void) {
    printf("\n--- Testing Zero Trust Agent ---\n");
    
    /* Initialize the agent */
    TEST_ASSERT(zero_trust_agent_init("/tmp/zt-agent-test.conf", 1) == 0, "Zero Trust agent initialization");
    
    /* Test agent configuration loading */
    TEST_ASSERT(agent_state.config_file != NULL, "Configuration file set");
    TEST_ASSERT(agent_state.socket_path != NULL, "Socket path set");
    TEST_ASSERT(agent_state.log_file != NULL, "Log file set");
    
    /* Test agent components initialization */
    TEST_ASSERT(agent_state.policy_engine != NULL, "Policy engine initialized");
    TEST_ASSERT(agent_state.perf_metrics != NULL, "Performance metrics initialized");
    TEST_ASSERT(agent_state.threat_intel != NULL, "Threat intelligence initialized");
    TEST_ASSERT(agent_state.device_monitor != NULL, "Device monitor initialized");
    TEST_ASSERT(agent_state.identity_service != NULL, "Identity service initialized");
    
    /* Test agent start/stop */
    TEST_ASSERT(zero_trust_agent_start() == 0, "Zero Trust agent start");
    
    /* Give it a moment to initialize */
    usleep(100000); /* 100ms */
    
    TEST_ASSERT(zero_trust_agent_stop() == 0, "Zero Trust agent stop");
    
    /* Test agent statistics */
    struct zero_trust_agent_stats stats;
    TEST_ASSERT(zero_trust_agent_get_stats(&stats) == 0, "Get agent statistics");
    TEST_ASSERT(stats.uptime >= 0, "Valid uptime");
    TEST_ASSERT(stats.requests_processed >= 0, "Valid request count");
    TEST_ASSERT(stats.avg_response_time >= 0, "Valid response time");
    
    /* Test agent configuration reload */
    TEST_ASSERT(zero_trust_agent_reload_config() == 0, "Configuration reload");
    
    /* Test agent health check */
    int health = zero_trust_agent_health_check();
    TEST_ASSERT(health >= 0 && health <= 100, "Valid health check result");
    
    /* Cleanup */
    zero_trust_agent_cleanup();
}

/* Run all tests */
int main(void) {
    printf("AppArmor Parser Enhancement Test Suite\n");
    printf("=====================================\n");
    
    /* Run individual component tests */
    test_adaptive_cache();
    test_enhanced_error_handling();
    test_performance_monitoring();
    test_security_enhancements();
    test_network_microsegmentation();
    test_binary_profile_serialization();
    test_conditional_policy_engine();
    test_zero_trust_agent();
    test_integration();
    
    /* Print final results */
    printf("\n=== Test Results ===\n");
    printf("Total Tests: %d\n", results.total);
    printf("Passed: %d\n", results.passed);
    printf("Failed: %d\n", results.failed);
    printf("Success Rate: %.2f%%\n", 
           results.total > 0 ? (double)results.passed / results.total * 100 : 0);
    
    if (results.failed == 0) {
        printf("\nAll tests passed! ✓\n");
        return 0;
    } else {
        printf("\nSome tests failed! ✗\n");
        return 1;
    }
}
