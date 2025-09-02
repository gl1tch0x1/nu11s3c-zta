/*
 * Performance Monitoring and Optimization System
 * 
 * Provides real-time performance monitoring, profiling, and automatic
 * optimization suggestions for the AppArmor parser.
 */

#ifndef PERFORMANCE_MONITOR_H
#define PERFORMANCE_MONITOR_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Performance metrics */
typedef struct {
    uint64_t total_time_us;
    uint64_t min_time_us;
    uint64_t max_time_us;
    uint64_t call_count;
    double avg_time_us;
    double std_dev_us;
    time_t first_call;
    time_t last_call;
} performance_metric_t;

/* Memory usage tracking */
typedef struct {
    size_t peak_memory;
    size_t current_memory;
    size_t total_allocations;
    size_t total_deallocations;
    size_t allocation_count;
    size_t deallocation_count;
    time_t peak_time;
} memory_metric_t;

/* CPU usage tracking */
typedef struct {
    double cpu_usage_percent;
    uint64_t user_time_us;
    uint64_t system_time_us;
    uint64_t total_time_us;
    time_t measurement_time;
} cpu_metric_t;

/* Performance profile for a function/operation */
typedef struct {
    char *name;
    performance_metric_t metric;
    memory_metric_t memory;
    cpu_metric_t cpu;
    struct performance_profile *parent;
    struct performance_profile *children;
    struct performance_profile *next;
} performance_profile_t;

/* Optimization suggestion */
typedef struct {
    char *description;
    char *impact;
    int priority; /* 1-10, 10 being highest */
    char *implementation;
} optimization_suggestion_t;

/* Performance monitor configuration */
typedef struct {
    int enable_profiling;
    int enable_memory_tracking;
    int enable_cpu_tracking;
    int auto_optimize;
    double optimization_threshold; /* Minimum improvement to apply */
    size_t max_profiles;
    time_t report_interval;
} monitor_config_t;

/* Function prototypes */
void performance_monitor_init(const monitor_config_t *config);
void performance_monitor_cleanup(void);
void performance_monitor_start_profile(const char *name);
void performance_monitor_end_profile(const char *name);
void performance_monitor_record_memory_allocation(size_t size);
void performance_monitor_record_memory_deallocation(size_t size);
void performance_monitor_update_cpu_usage(void);

/* Profile management */
performance_profile_t *performance_monitor_get_profile(const char *name);
void performance_monitor_print_profile(const char *name);
void performance_monitor_print_all_profiles(void);
void performance_monitor_export_profiles(const char *filename);

/* Optimization */
optimization_suggestion_t *performance_monitor_analyze_performance(void);
void performance_monitor_apply_optimizations(void);
void performance_monitor_print_suggestions(void);

/* Statistics */
void performance_monitor_print_summary(void);
void performance_monitor_reset_stats(void);
double performance_monitor_get_total_time(void);
size_t performance_monitor_get_peak_memory(void);

/* Utility macros */
#define PERFORMANCE_PROFILE_START(name) \
    performance_monitor_start_profile(name)

#define PERFORMANCE_PROFILE_END(name) \
    performance_monitor_end_profile(name)

#define PERFORMANCE_PROFILE_SCOPE(name) \
    performance_monitor_start_profile(name); \
    __attribute__((cleanup(performance_monitor_end_profile))) char _profile_scope = 0

/* Memory tracking macros */
#define PERFORMANCE_MALLOC(size) \
    ({ \
        void *_ptr = malloc(size); \
        if (_ptr) performance_monitor_record_memory_allocation(size); \
        _ptr; \
    })

#define PERFORMANCE_FREE(ptr) \
    do { \
        if (ptr) { \
            performance_monitor_record_memory_deallocation(sizeof(*ptr)); \
            free(ptr); \
        } \
    } while(0)

#ifdef __cplusplus
}
#endif

#endif /* PERFORMANCE_MONITOR_H */
