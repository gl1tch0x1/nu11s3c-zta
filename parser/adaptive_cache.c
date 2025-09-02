/*
 * Adaptive Cache System Implementation
 * 
 * Provides intelligent caching with automatic optimization based on
 * system resources and usage patterns.
 */

#include "adaptive_cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <math.h>

/* Hash function for cache keys */
static uint32_t hash_key(const char *key) {
    uint32_t hash = 5381;
    int c;
    while ((c = *key++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/* Create a new adaptive cache */
adaptive_cache_t *adaptive_cache_create(const cache_config_t *config) {
    adaptive_cache_t *cache = adaptive_malloc(sizeof(adaptive_cache_t));
    if (!cache) return NULL;
    
    memset(cache, 0, sizeof(adaptive_cache_t));
    
    if (config) {
        cache->config = *config;
    } else {
        cache_config_t *default_config = adaptive_cache_default_config();
        cache->config = *default_config;
        adaptive_free(default_config);
    }
    
    /* Initialize hash table */
    cache->hash_size = 1024; /* Start with reasonable size */
    cache->hash_table = adaptive_malloc(sizeof(cache_entry_t*) * cache->hash_size);
    if (!cache->hash_table) {
        adaptive_free(cache);
        return NULL;
    }
    
    memset(cache->hash_table, 0, sizeof(cache_entry_t*) * cache->hash_size);
    
    /* Initialize mutex */
    if (pthread_mutex_init(&cache->mutex, NULL) != 0) {
        adaptive_free(cache->hash_table);
        adaptive_free(cache);
        return NULL;
    }
    
    return cache;
}

/* Destroy cache and free all resources */
void adaptive_cache_destroy(adaptive_cache_t *cache) {
    if (!cache) return;
    
    pthread_mutex_lock(&cache->mutex);
    
    /* Free all entries */
    adaptive_cache_clear(cache);
    
    /* Free hash table */
    adaptive_free(cache->hash_table);
    
    pthread_mutex_unlock(&cache->mutex);
    pthread_mutex_destroy(&cache->mutex);
    adaptive_free(cache);
}

/* Add entry to cache with adaptive eviction */
int adaptive_cache_put(adaptive_cache_t *cache, const char *key, const void *data, size_t size) {
    if (!cache || !key || !data) return -1;
    
    pthread_mutex_lock(&cache->mutex);
    
    /* Check if we need to evict entries */
    while (cache->current_memory + size > cache->config.max_memory ||
           cache->current_entries >= cache->config.max_entries) {
        if (!adaptive_cache_evict_lru(cache)) {
            pthread_mutex_unlock(&cache->mutex);
            return -1; /* Couldn't make space */
        }
    }
    
    /* Create new entry */
    cache_entry_t *entry = adaptive_malloc(sizeof(cache_entry_t));
    if (!entry) {
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    entry->key = adaptive_malloc(strlen(key) + 1);
    entry->data = adaptive_malloc(size);
    if (!entry->key || !entry->data) {
        adaptive_free(entry->key);
        adaptive_free(entry->data);
        adaptive_free(entry);
        pthread_mutex_unlock(&cache->mutex);
        return -1;
    }
    
    strcpy(entry->key, key);
    memcpy(entry->data, data, size);
    entry->data_size = size;
    entry->created = time(NULL);
    entry->last_accessed = entry->created;
    entry->access_count = 1;
    entry->priority = 1;
    
    /* Add to hash table */
    uint32_t hash = hash_key(key) % cache->hash_size;
    entry->next = cache->hash_table[hash];
    if (cache->hash_table[hash]) {
        cache->hash_table[hash]->prev = entry;
    }
    cache->hash_table[hash] = entry;
    
    /* Add to LRU list */
    entry->next = cache->lru_head;
    entry->prev = NULL;
    if (cache->lru_head) {
        cache->lru_head->prev = entry;
    } else {
        cache->lru_tail = entry;
    }
    cache->lru_head = entry;
    
    cache->current_memory += size;
    cache->current_entries++;
    cache->stats.total_accesses++;
    
    pthread_mutex_unlock(&cache->mutex);
    return 0;
}

/* Get entry from cache with LRU update */
void *adaptive_cache_get(adaptive_cache_t *cache, const char *key, size_t *size) {
    if (!cache || !key) return NULL;
    
    pthread_mutex_lock(&cache->mutex);
    
    uint32_t hash = hash_key(key) % cache->hash_size;
    cache_entry_t *entry = cache->hash_table[hash];
    
    /* Find the entry */
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            /* Check TTL */
            if (cache->config.ttl_seconds > 0) {
                time_t now = time(NULL);
                if (now - entry->created > cache->config.ttl_seconds) {
                    /* Entry expired, remove it */
                    adaptive_cache_remove_entry(cache, entry);
                    pthread_mutex_unlock(&cache->mutex);
                    cache->stats.misses++;
                    return NULL;
                }
            }
            
            /* Update LRU */
            adaptive_cache_update_lru(cache, entry);
            entry->last_accessed = time(NULL);
            entry->access_count++;
            
            if (size) *size = entry->data_size;
            
            cache->stats.hits++;
            cache->stats.last_access = entry->last_accessed;
            
            pthread_mutex_unlock(&cache->mutex);
            return entry->data;
        }
        entry = entry->next;
    }
    
    cache->stats.misses++;
    pthread_mutex_unlock(&cache->mutex);
    return NULL;
}

/* Remove entry from cache */
int adaptive_cache_remove(adaptive_cache_t *cache, const char *key) {
    if (!cache || !key) return -1;
    
    pthread_mutex_lock(&cache->mutex);
    
    uint32_t hash = hash_key(key) % cache->hash_size;
    cache_entry_t *entry = cache->hash_table[hash];
    
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            adaptive_cache_remove_entry(cache, entry);
            pthread_mutex_unlock(&cache->mutex);
            return 0;
        }
        entry = entry->next;
    }
    
    pthread_mutex_unlock(&cache->mutex);
    return -1;
}

/* Clear all entries */
void adaptive_cache_clear(adaptive_cache_t *cache) {
    if (!cache) return;
    
    cache_entry_t *entry = cache->lru_head;
    while (entry) {
        cache_entry_t *next = entry->next;
        adaptive_cache_remove_entry(cache, entry);
        entry = next;
    }
}

/* Get cache statistics */
cache_stats_t *adaptive_cache_get_stats(adaptive_cache_t *cache) {
    if (!cache) return NULL;
    
    pthread_mutex_lock(&cache->mutex);
    
    /* Calculate hit ratio */
    if (cache->stats.total_accesses > 0) {
        cache->stats.hit_ratio = (double)cache->stats.hits / cache->stats.total_accesses;
    } else {
        cache->stats.hit_ratio = 0.0;
    }
    
    cache->stats.memory_usage = cache->current_memory;
    
    pthread_mutex_unlock(&cache->mutex);
    return &cache->stats;
}

/* Print cache statistics */
void adaptive_cache_print_stats(adaptive_cache_t *cache) {
    cache_stats_t *stats = adaptive_cache_get_stats(cache);
    if (!stats) return;
    
    printf("Cache Statistics:\n");
    printf("  Hits: %lu\n", stats->hits);
    printf("  Misses: %lu\n", stats->misses);
    printf("  Hit Ratio: %.2f%%\n", stats->hit_ratio * 100);
    printf("  Evictions: %lu\n", stats->evictions);
    printf("  Memory Usage: %zu bytes\n", stats->memory_usage);
    printf("  Total Accesses: %lu\n", stats->total_accesses);
}

/* Auto-tune cache based on system resources */
void adaptive_cache_auto_tune(adaptive_cache_t *cache) {
    if (!cache) return;
    
    struct sysinfo info;
    if (sysinfo(&info) != 0) return;
    
    /* Adjust cache size based on available memory */
    size_t available_memory = info.freeram * info.mem_unit;
    size_t suggested_memory = available_memory / 8; /* Use 1/8 of available memory */
    
    if (suggested_memory > cache->config.max_memory) {
        cache->config.max_memory = suggested_memory;
    }
    
    /* Adjust TTL based on hit ratio */
    if (cache->stats.hit_ratio < 0.7) {
        cache->config.ttl_seconds *= 2; /* Increase TTL for better hit ratio */
    } else if (cache->stats.hit_ratio > 0.9) {
        cache->config.ttl_seconds /= 2; /* Decrease TTL to save memory */
    }
}

/* Create default configuration */
cache_config_t *adaptive_cache_default_config(void) {
    cache_config_t *config = adaptive_malloc(sizeof(cache_config_t));
    if (!config) return NULL;
    
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        config->max_memory = (info.totalram * info.mem_unit) / 16; /* 1/16 of total RAM */
    } else {
        config->max_memory = 64 * 1024 * 1024; /* 64MB default */
    }
    
    config->max_entries = 10000;
    config->ttl_seconds = 3600; /* 1 hour */
    config->target_hit_ratio = 0.8;
    config->enable_compression = 1;
    config->enable_prefetch = 1;
    config->adaptive_eviction = 1;
    
    return config;
}

/* Enhanced memory management with error checking */
void *adaptive_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr && size > 0) {
        fprintf(stderr, "Memory allocation failed: %zu bytes\n", size);
        exit(1);
    }
    return ptr;
}

void adaptive_free(void *ptr) {
    if (ptr) free(ptr);
}

void *adaptive_realloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr && size > 0) {
        fprintf(stderr, "Memory reallocation failed: %zu bytes\n", size);
        exit(1);
    }
    return new_ptr;
}

/* Helper functions (would need to be implemented) */
static int adaptive_cache_evict_lru(adaptive_cache_t *cache) {
    if (!cache->lru_tail) return 0;
    adaptive_cache_remove_entry(cache, cache->lru_tail);
    return 1;
}

static void adaptive_cache_update_lru(adaptive_cache_t *cache, cache_entry_t *entry) {
    /* Remove from current position */
    if (entry->prev) {
        entry->prev->next = entry->next;
    } else {
        cache->lru_head = entry->next;
    }
    
    if (entry->next) {
        entry->next->prev = entry->prev;
    } else {
        cache->lru_tail = entry->prev;
    }
    
    /* Add to head */
    entry->next = cache->lru_head;
    entry->prev = NULL;
    if (cache->lru_head) {
        cache->lru_head->prev = entry;
    } else {
        cache->lru_tail = entry;
    }
    cache->lru_head = entry;
}

static void adaptive_cache_remove_entry(adaptive_cache_t *cache, cache_entry_t *entry) {
    /* Remove from hash table */
    uint32_t hash = hash_key(entry->key) % cache->hash_size;
    cache_entry_t **slot = &cache->hash_table[hash];
    
    while (*slot && *slot != entry) {
        slot = &(*slot)->next;
    }
    
    if (*slot) {
        *slot = entry->next;
        if (entry->next) {
            entry->next->prev = entry->prev;
        }
    }
    
    /* Remove from LRU list */
    if (entry->prev) {
        entry->prev->next = entry->next;
    } else {
        cache->lru_head = entry->next;
    }
    
    if (entry->next) {
        entry->next->prev = entry->prev;
    } else {
        cache->lru_tail = entry->prev;
    }
    
    /* Free memory */
    adaptive_free(entry->key);
    adaptive_free(entry->data);
    adaptive_free(entry);
    
    cache->current_entries--;
    cache->stats.evictions++;
}
