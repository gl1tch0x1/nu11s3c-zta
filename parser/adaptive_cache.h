/*
 * Adaptive Cache System for AppArmor Parser
 * 
 * This header provides an intelligent caching system that adapts to system
 * resources and usage patterns to optimize performance.
 */

#ifndef ADAPTIVE_CACHE_H
#define ADAPTIVE_CACHE_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Cache statistics for adaptive behavior */
typedef struct {
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint64_t total_accesses;
    time_t last_access;
    size_t memory_usage;
    double hit_ratio;
} cache_stats_t;

/* Cache entry with metadata */
typedef struct cache_entry {
    char *key;
    void *data;
    size_t data_size;
    time_t created;
    time_t last_accessed;
    uint32_t access_count;
    uint32_t priority;
    struct cache_entry *next;
    struct cache_entry *prev;
} cache_entry_t;

/* Adaptive cache configuration */
typedef struct {
    size_t max_memory;
    size_t max_entries;
    time_t ttl_seconds;
    double target_hit_ratio;
    int enable_compression;
    int enable_prefetch;
    int adaptive_eviction;
} cache_config_t;

/* Main cache structure */
typedef struct {
    cache_entry_t **hash_table;
    cache_entry_t *lru_head;
    cache_entry_t *lru_tail;
    cache_stats_t stats;
    cache_config_t config;
    pthread_mutex_t mutex;
    size_t current_memory;
    size_t current_entries;
    uint32_t hash_size;
} adaptive_cache_t;

/* Function prototypes */
adaptive_cache_t *adaptive_cache_create(const cache_config_t *config);
void adaptive_cache_destroy(adaptive_cache_t *cache);
int adaptive_cache_put(adaptive_cache_t *cache, const char *key, const void *data, size_t size);
void *adaptive_cache_get(adaptive_cache_t *cache, const char *key, size_t *size);
int adaptive_cache_remove(adaptive_cache_t *cache, const char *key);
void adaptive_cache_clear(adaptive_cache_t *cache);
cache_stats_t *adaptive_cache_get_stats(adaptive_cache_t *cache);
void adaptive_cache_print_stats(adaptive_cache_t *cache);
int adaptive_cache_optimize(adaptive_cache_t *cache);

/* Configuration helpers */
cache_config_t *adaptive_cache_default_config(void);
void adaptive_cache_auto_tune(adaptive_cache_t *cache);

/* Memory management helpers */
void *adaptive_malloc(size_t size);
void adaptive_free(void *ptr);
void *adaptive_realloc(void *ptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* ADAPTIVE_CACHE_H */
