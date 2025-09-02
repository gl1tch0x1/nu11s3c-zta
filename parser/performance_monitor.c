/*
 * Performance Monitoring and Optimization System Implementation
 * 
 * Provides real-time performance monitoring, profiling, and automatic
 * optimization suggestions for the AppArmor parser.
 */

#include "performance_monitor.h"
#include "enhanced_error.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <pthread.h>
#include <math.h>

/* Global performance monitor state */
static struct {
    monitor_config_t config;
    performance_profile_t *profiles;
    memory_metric_t memory_stats;
    cpu_metric_t cpu_stats;
    pthread_mutex_t mutex;
    int initialized;
    time_t start_time;
} monitor_state = {0};

/* Hash function for profile names */
static uint32_t hash_profile_name(const char *name) {
    uint32_t hash = 5381;
    int c;
    while ((c = *name++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/* Get current time in microseconds */
static uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* Get current CPU usage */
static double get_cpu_usage(void) {
    static struct rusage prev_usage = {0};
    static time_t prev_time = 0;
    
    struct rusage current_usage;
    time_t current_time = time(NULL);
    
    if (getrusage(RUSAGE_SELF, &current_usage) != 0) {
        return 0.0;
    }
    
    if (prev_time == 0) {
        prev_usage = current_usage;
        prev_time = current_time;
        return 0.0;
    }
    
    double user_time = (current_usage.ru_utime.tv_sec - prev_usage.ru_utime.tv_sec) * 1000000.0 +
                      (current_usage.ru_utime.tv_usec - prev_usage.ru_utime.tv_usec);
    double system_time = (current_usage.ru_stime.tv_sec - prev_usage.ru_stime.tv_sec) * 1000000.0 +
                        (current_usage.ru_stime.tv_usec - prev_usage.ru_stime.tv_usec);
    double total_time = (current_time - prev_time) * 1000000.0;
    
    prev_usage = current_usage;
    prev_time = current_time;
    
    if (total_time > 0) {
        return ((user_time + system_time) / total_time) * 100.0;
    }
    
    return 0.0;
}

/* Initialize performance monitor */
void performance_monitor_init(const monitor_config_t *config) {
    if (monitor_state.initialized) return;
    
    memset(&monitor_state, 0, sizeof(monitor_state));
    
    if (config) {
        monitor_state.config = *config;
    } else {
        /* Default configuration */
        monitor_state.config.enable_profiling = 1;
        monitor_state.config.enable_memory_tracking = 1;
        monitor_state.config.enable_cpu_tracking = 1;
        monitor_state.config.auto_optimize = 0;
        monitor_state.config.optimization_threshold = 0.1;
        monitor_state.config.max_profiles = 1000;
        monitor_state.config.report_interval = 60;
    }
    
    if (pthread_mutex_init(&monitor_state.mutex, NULL) != 0) {
        ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_SYSTEM, 1, "Failed to initialize performance monitor mutex");
        return;
    }
    
    monitor_state.start_time = time(NULL);
    monitor_state.initialized = 1;
    
    ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Performance monitor initialized");
}

/* Cleanup performance monitor */
void performance_monitor_cleanup(void) {
    if (!monitor_state.initialized) return;
    
    pthread_mutex_lock(&monitor_state.mutex);
    
    /* Free all profiles */
    performance_profile_t *profile = monitor_state.profiles;
    while (profile) {
        performance_profile_t *next = profile->next;
        free(profile->name);
        free(profile);
        profile = next;
    }
    
    pthread_mutex_unlock(&monitor_state.mutex);
    pthread_mutex_destroy(&monitor_state.mutex);
    
    monitor_state.initialized = 0;
    ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Performance monitor cleaned up");
}

/* Find or create profile */
static performance_profile_t *find_or_create_profile(const char *name) {
    if (!name) return NULL;
    
    uint32_t hash = hash_profile_name(name);
    performance_profile_t *profile = monitor_state.profiles;
    
    /* Find existing profile */
    while (profile) {
        if (strcmp(profile->name, name) == 0) {
            return profile;
        }
        profile = profile->next;
    }
    
    /* Create new profile */
    profile = malloc(sizeof(performance_profile_t));
    if (!profile) {
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for performance profile");
        return NULL;
    }
    
    memset(profile, 0, sizeof(performance_profile_t));
    profile->name = strdup(name);
    if (!profile->name) {
        free(profile);
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for profile name");
        return NULL;
    }
    
    profile->metric.min_time_us = UINT64_MAX;
    profile->next = monitor_state.profiles;
    monitor_state.profiles = profile;
    
    return profile;
}

/* Start profiling */
void performance_monitor_start_profile(const char *name) {
    if (!monitor_state.initialized || !monitor_state.config.enable_profiling) return;
    
    pthread_mutex_lock(&monitor_state.mutex);
    
    performance_profile_t *profile = find_or_create_profile(name);
    if (profile) {
        profile->metric.first_call = time(NULL);
        profile->metric.last_call = profile->metric.first_call;
    }
    
    pthread_mutex_unlock(&monitor_state.mutex);
}

/* End profiling */
void performance_monitor_end_profile(const char *name) {
    if (!monitor_state.initialized || !monitor_state.config.enable_profiling) return;
    
    pthread_mutex_lock(&monitor_state.mutex);
    
    performance_profile_t *profile = find_or_create_profile(name);
    if (profile) {
        uint64_t end_time = get_time_us();
        uint64_t duration = end_time - profile->metric.last_call;
        
        profile->metric.total_time_us += duration;
        profile->metric.call_count++;
        profile->metric.last_call = time(NULL);
        
        if (duration < profile->metric.min_time_us) {
            profile->metric.min_time_us = duration;
        }
        if (duration > profile->metric.max_time_us) {
            profile->metric.max_time_us = duration;
        }
        
        if (profile->metric.call_count > 0) {
            profile->metric.avg_time_us = (double)profile->metric.total_time_us / profile->metric.call_count;
        }
    }
    
    pthread_mutex_unlock(&monitor_state.mutex);
}

/* Record memory allocation */
void performance_monitor_record_memory_allocation(size_t size) {
    if (!monitor_state.initialized || !monitor_state.config.enable_memory_tracking) return;
    
    pthread_mutex_lock(&monitor_state.mutex);
    
    monitor_state.memory_stats.current_memory += size;
    monitor_state.memory_stats.total_allocations += size;
    monitor_state.memory_stats.allocation_count++;
    
    if (monitor_state.memory_stats.current_memory > monitor_state.memory_stats.peak_memory) {
        monitor_state.memory_stats.peak_memory = monitor_state.memory_stats.current_memory;
        monitor_state.memory_stats.peak_time = time(NULL);
    }
    
    pthread_mutex_unlock(&monitor_state.mutex);
}

/* Record memory deallocation */
void performance_monitor_record_memory_deallocation(size_t size) {
    if (!monitor_state.initialized || !monitor_state.config.enable_memory_tracking) return;
    
    pthread_mutex_lock(&monitor_state.mutex);
    
    if (monitor_state.memory_stats.current_memory >= size) {
        monitor_state.memory_stats.current_memory -= size;
    } else {
        monitor_state.memory_stats.current_memory = 0;
    }
    
    monitor_state.memory_stats.total_deallocations += size;
    monitor_state.memory_stats.deallocation_count++;
    
    pthread_mutex_unlock(&monitor_state.mutex);
}

/* Update CPU usage */
void performance_monitor_update_cpu_usage(void) {
    if (!monitor_state.initialized || !monitor_state.config.enable_cpu_tracking) return;
    
    pthread_mutex_lock(&monitor_state.mutex);
    
    monitor_state.cpu_stats.cpu_usage_percent = get_cpu_usage();
    monitor_state.cpu_stats.measurement_time = time(NULL);
    
    pthread_mutex_unlock(&monitor_state.mutex);
}

/* Get profile by name */
performance_profile_t *performance_monitor_get_profile(const char *name) {
    if (!monitor_state.initialized || !name) return NULL;
    
    pthread_mutex_lock(&monitor_state.mutex);
    
    performance_profile_t *profile = monitor_state.profiles;
    while (profile) {
        if (strcmp(profile->name, name) == 0) {
            pthread_mutex_unlock(&monitor_state.mutex);
            return profile;
        }
        profile = profile->next;
    }
    
    pthread_mutex_unlock(&monitor_state.mutex);
    return NULL;
}

/* Print profile information */
void performance_monitor_print_profile(const char *name) {
    performance_profile_t *profile = performance_monitor_get_profile(name);
    if (!profile) {
        printf("Profile '%s' not found\n", name);
        return;
    }
    
    printf("Performance Profile: %s\n", profile->name);
    printf("  Call Count: %lu\n", profile->metric.call_count);
    printf("  Total Time: %lu μs\n", profile->metric.total_time_us);
    printf("  Average Time: %.2f μs\n", profile->metric.avg_time_us);
    printf("  Min Time: %lu μs\n", profile->metric.min_time_us);
    printf("  Max Time: %lu μs\n", profile->metric.max_time_us);
    printf("  First Call: %s", ctime(&profile->metric.first_call));
    printf("  Last Call: %s", ctime(&profile->metric.last_call));
}

/* Print all profiles */
void performance_monitor_print_all_profiles(void) {
    if (!monitor_state.initialized) return;
    
    pthread_mutex_lock(&monitor_state.mutex);
    
    performance_profile_t *profile = monitor_state.profiles;
    while (profile) {
        performance_monitor_print_profile(profile->name);
        printf("\n");
        profile = profile->next;
    }
    
    pthread_mutex_unlock(&monitor_state.mutex);
}

/* Export profiles to file */
void performance_monitor_export_profiles(const char *filename) {
    if (!monitor_state.initialized || !filename) return;
    
    FILE *file = fopen(filename, "w");
    if (!file) {
        ENHANCED_ERROR_FILE(2, "Failed to open file for profile export: %s", filename);
        return;
    }
    
    pthread_mutex_lock(&monitor_state.mutex);
    
    fprintf(file, "Performance Profiles Export\n");
    fprintf(file, "Generated: %s\n", ctime(&monitor_state.start_time));
    fprintf(file, "=====================================\n\n");
    
    performance_profile_t *profile = monitor_state.profiles;
    while (profile) {
        fprintf(file, "Profile: %s\n", profile->name);
        fprintf(file, "  Call Count: %lu\n", profile->metric.call_count);
        fprintf(file, "  Total Time: %lu μs\n", profile->metric.total_time_us);
        fprintf(file, "  Average Time: %.2f μs\n", profile->metric.avg_time_us);
        fprintf(file, "  Min Time: %lu μs\n", profile->metric.min_time_us);
        fprintf(file, "  Max Time: %lu μs\n", profile->metric.max_time_us);
        fprintf(file, "  First Call: %s", ctime(&profile->metric.first_call));
        fprintf(file, "  Last Call: %s", ctime(&profile->metric.last_call));
        fprintf(file, "\n");
        
        profile = profile->next;
    }
    
    pthread_mutex_unlock(&monitor_state.mutex);
    fclose(file);
    
    ENHANCED_INFO(ERROR_CATEGORY_FILE_IO, 1, "Performance profiles exported to: %s", filename);
}

/* Analyze performance and suggest optimizations */
optimization_suggestion_t *performance_monitor_analyze_performance(void) {
    if (!monitor_state.initialized) return NULL;
    
    pthread_mutex_lock(&monitor_state.mutex);
    
    /* Simple analysis - find slowest functions */
    performance_profile_t *profile = monitor_state.profiles;
    performance_profile_t *slowest = NULL;
    double max_avg_time = 0.0;
    
    while (profile) {
        if (profile->metric.avg_time_us > max_avg_time) {
            max_avg_time = profile->metric.avg_time_us;
            slowest = profile;
        }
        profile = profile->next;
    }
    
    pthread_mutex_unlock(&monitor_state.mutex);
    
    if (slowest && max_avg_time > 1000.0) { /* More than 1ms average */
        optimization_suggestion_t *suggestion = malloc(sizeof(optimization_suggestion_t));
        if (suggestion) {
            suggestion->description = malloc(256);
            suggestion->impact = malloc(256);
            suggestion->implementation = malloc(256);
            
            if (suggestion->description && suggestion->impact && suggestion->implementation) {
                snprintf(suggestion->description, 256, "Function '%s' has high average execution time", slowest->name);
                snprintf(suggestion->impact, 256, "Potential 10-20%% performance improvement");
                snprintf(suggestion->implementation, 256, "Consider caching, algorithm optimization, or reducing I/O operations");
                suggestion->priority = 8;
            } else {
                free(suggestion->description);
                free(suggestion->impact);
                free(suggestion->implementation);
                free(suggestion);
                suggestion = NULL;
            }
        }
        return suggestion;
    }
    
    return NULL;
}

/* Apply optimizations */
void performance_monitor_apply_optimizations(void) {
    if (!monitor_state.initialized || !monitor_state.config.auto_optimize) return;
    
    ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Auto-optimization not implemented yet");
}

/* Print optimization suggestions */
void performance_monitor_print_suggestions(void) {
    optimization_suggestion_t *suggestion = performance_monitor_analyze_performance();
    if (suggestion) {
        printf("Performance Optimization Suggestion:\n");
        printf("  Description: %s\n", suggestion->description);
        printf("  Impact: %s\n", suggestion->impact);
        printf("  Implementation: %s\n", suggestion->implementation);
        printf("  Priority: %d/10\n", suggestion->priority);
        
        free(suggestion->description);
        free(suggestion->impact);
        free(suggestion->implementation);
        free(suggestion);
    } else {
        printf("No performance optimizations suggested at this time.\n");
    }
}

/* Print performance summary */
void performance_monitor_print_summary(void) {
    if (!monitor_state.initialized) return;
    
    pthread_mutex_lock(&monitor_state.mutex);
    
    printf("Performance Monitor Summary\n");
    printf("==========================\n");
    printf("Uptime: %ld seconds\n", time(NULL) - monitor_state.start_time);
    printf("Memory Usage: %zu bytes (Peak: %zu bytes)\n", 
           monitor_state.memory_stats.current_memory,
           monitor_state.memory_stats.peak_memory);
    printf("CPU Usage: %.2f%%\n", monitor_state.cpu_stats.cpu_usage_percent);
    printf("Total Allocations: %zu bytes (%zu allocations)\n",
           monitor_state.memory_stats.total_allocations,
           monitor_state.memory_stats.allocation_count);
    printf("Total Deallocations: %zu bytes (%zu deallocations)\n",
           monitor_state.memory_stats.total_deallocations,
           monitor_state.memory_stats.deallocation_count);
    
    /* Count profiles */
    int profile_count = 0;
    performance_profile_t *profile = monitor_state.profiles;
    while (profile) {
        profile_count++;
        profile = profile->next;
    }
    printf("Active Profiles: %d\n", profile_count);
    
    pthread_mutex_unlock(&monitor_state.mutex);
}

/* Reset statistics */
void performance_monitor_reset_stats(void) {
    if (!monitor_state.initialized) return;
    
    pthread_mutex_lock(&monitor_state.mutex);
    
    /* Reset memory stats */
    memset(&monitor_state.memory_stats, 0, sizeof(monitor_state.memory_stats));
    
    /* Reset CPU stats */
    memset(&monitor_state.cpu_stats, 0, sizeof(monitor_state.cpu_stats));
    
    /* Reset profile stats */
    performance_profile_t *profile = monitor_state.profiles;
    while (profile) {
        memset(&profile->metric, 0, sizeof(profile->metric));
        profile->metric.min_time_us = UINT64_MAX;
        profile = profile->next;
    }
    
    monitor_state.start_time = time(NULL);
    
    pthread_mutex_unlock(&monitor_state.mutex);
    
    ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Performance statistics reset");
}

/* Get total execution time */
double performance_monitor_get_total_time(void) {
    if (!monitor_state.initialized) return 0.0;
    
    pthread_mutex_lock(&monitor_state.mutex);
    
    uint64_t total_time = 0;
    performance_profile_t *profile = monitor_state.profiles;
    while (profile) {
        total_time += profile->metric.total_time_us;
        profile = profile->next;
    }
    
    pthread_mutex_unlock(&monitor_state.mutex);
    
    return total_time / 1000000.0; /* Convert to seconds */
}

/* Get peak memory usage */
size_t performance_monitor_get_peak_memory(void) {
    if (!monitor_state.initialized) return 0;
    
    pthread_mutex_lock(&monitor_state.mutex);
    size_t peak = monitor_state.memory_stats.peak_memory;
    pthread_mutex_unlock(&monitor_state.mutex);
    
    return peak;
}
