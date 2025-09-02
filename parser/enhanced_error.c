/*
 * Enhanced Error Handling System Implementation
 * 
 * Provides comprehensive error handling with context, recovery mechanisms,
 * and detailed logging for better debugging and user experience.
 */

#include "enhanced_error.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <pthread.h>

/* Global error handling state */
static struct {
    error_handler_t handler;
    error_level_t min_level;
    FILE *log_file;
    error_stats_t stats;
    pthread_mutex_t mutex;
    int initialized;
} error_state = {0};

/* Error code to string mapping */
static const char *error_code_strings[] = {
    "SUCCESS",
    "MEMORY_ALLOCATION_FAILED",
    "FILE_NOT_FOUND",
    "PERMISSION_DENIED",
    "INVALID_FORMAT",
    "PARSER_SYNTAX_ERROR",
    "KERNEL_INTERFACE_ERROR",
    "NETWORK_ERROR",
    "VALIDATION_FAILED",
    "SYSTEM_ERROR",
    "UNKNOWN_ERROR"
};

/* Initialize error handling system */
void enhanced_error_init(void) {
    if (error_state.initialized) return;
    
    memset(&error_state, 0, sizeof(error_state));
    error_state.min_level = ERROR_LEVEL_INFO;
    error_state.log_file = stderr;
    
    if (pthread_mutex_init(&error_state.mutex, NULL) != 0) {
        fprintf(stderr, "Failed to initialize error handling mutex\n");
        return;
    }
    
    error_state.initialized = 1;
    error_state.stats.first_error = time(NULL);
}

/* Cleanup error handling system */
void enhanced_error_cleanup(void) {
    if (!error_state.initialized) return;
    
    pthread_mutex_lock(&error_state.mutex);
    
    if (error_state.log_file && error_state.log_file != stderr && error_state.log_file != stdout) {
        fclose(error_state.log_file);
        error_state.log_file = NULL;
    }
    
    pthread_mutex_unlock(&error_state.mutex);
    pthread_mutex_destroy(&error_state.mutex);
    
    error_state.initialized = 0;
}

/* Set custom error handler */
void enhanced_error_set_handler(error_handler_t handler) {
    if (!error_state.initialized) enhanced_error_init();
    
    pthread_mutex_lock(&error_state.mutex);
    error_state.handler = handler;
    pthread_mutex_unlock(&error_state.mutex);
}

/* Set minimum error level to report */
void enhanced_error_set_level(error_level_t min_level) {
    if (!error_state.initialized) enhanced_error_init();
    
    pthread_mutex_lock(&error_state.mutex);
    error_state.min_level = min_level;
    pthread_mutex_unlock(&error_state.mutex);
}

/* Set log file for error output */
void enhanced_error_set_log_file(const char *filename) {
    if (!error_state.initialized) enhanced_error_init();
    
    pthread_mutex_lock(&error_state.mutex);
    
    if (error_state.log_file && error_state.log_file != stderr && error_state.log_file != stdout) {
        fclose(error_state.log_file);
    }
    
    if (filename) {
        error_state.log_file = fopen(filename, "a");
        if (!error_state.log_file) {
            error_state.log_file = stderr;
        }
    } else {
        error_state.log_file = stderr;
    }
    
    pthread_mutex_unlock(&error_state.mutex);
}

/* Main error reporting function */
void enhanced_error_report(error_level_t level, error_category_t category,
                          const char *file, int line, const char *function,
                          uint32_t error_code, const char *format, ...) {
    if (!error_state.initialized) enhanced_error_init();
    
    if (level < error_state.min_level) return;
    
    va_list args;
    va_start(args, format);
    
    /* Create error context */
    error_context_t context = {0};
    context.file = file;
    context.line = line;
    context.function = function;
    context.timestamp = time(NULL);
    context.error_code = error_code;
    context.level = level;
    context.category = category;
    
    /* Format message */
    char message_buffer[1024];
    vsnprintf(message_buffer, sizeof(message_buffer), format, args);
    context.message = message_buffer;
    
    va_end(args);
    
    /* Update statistics */
    pthread_mutex_lock(&error_state.mutex);
    error_state.stats.total_errors++;
    error_state.stats.errors_by_level[level]++;
    error_state.stats.errors_by_category[category]++;
    error_state.stats.last_error = context.timestamp;
    pthread_mutex_unlock(&error_state.mutex);
    
    /* Call custom handler if set */
    if (error_state.handler) {
        error_state.handler(&context);
    } else {
        /* Default error handling */
        enhanced_error_default_handler(&context);
    }
}

/* Report error with full context */
void enhanced_error_report_with_context(error_level_t level, error_category_t category,
                                       const char *file, int line, const char *function,
                                       uint32_t error_code, const char *message,
                                       const char *details, const char *suggestion) {
    if (!error_state.initialized) enhanced_error_init();
    
    if (level < error_state.min_level) return;
    
    /* Create error context */
    error_context_t context = {0};
    context.file = file;
    context.line = line;
    context.function = function;
    context.timestamp = time(NULL);
    context.error_code = error_code;
    context.level = level;
    context.category = category;
    context.message = (char*)message;
    context.details = (char*)details;
    context.suggestion = (char*)suggestion;
    
    /* Update statistics */
    pthread_mutex_lock(&error_state.mutex);
    error_state.stats.total_errors++;
    error_state.stats.errors_by_level[level]++;
    error_state.stats.errors_by_category[category]++;
    error_state.stats.last_error = context.timestamp;
    pthread_mutex_unlock(&error_state.mutex);
    
    /* Call custom handler if set */
    if (error_state.handler) {
        error_state.handler(&context);
    } else {
        /* Default error handling */
        enhanced_error_default_handler(&context);
    }
}

/* Default error handler */
static void enhanced_error_default_handler(const error_context_t *context) {
    if (!context) return;
    
    pthread_mutex_lock(&error_state.mutex);
    FILE *output = error_state.log_file ? error_state.log_file : stderr;
    pthread_mutex_unlock(&error_state.mutex);
    
    /* Format timestamp */
    char timestamp_str[64];
    struct tm *tm_info = localtime(&context->timestamp);
    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    /* Print error information */
    fprintf(output, "[%s] %s: %s (%s:%d in %s)\n",
            timestamp_str,
            enhanced_error_level_to_string(context->level),
            context->message,
            context->file,
            context->line,
            context->function);
    
    if (context->details) {
        fprintf(output, "  Details: %s\n", context->details);
    }
    
    if (context->suggestion) {
        fprintf(output, "  Suggestion: %s\n", context->suggestion);
    }
    
    fprintf(output, "  Error Code: %u (%s)\n",
            context->error_code,
            enhanced_error_code_to_string(context->error_code));
    
    fflush(output);
    
    /* Send to syslog for critical errors */
    if (context->level >= ERROR_LEVEL_CRITICAL) {
        int priority = LOG_CRIT;
        switch (context->level) {
            case ERROR_LEVEL_CRITICAL: priority = LOG_CRIT; break;
            case ERROR_LEVEL_FATAL: priority = LOG_EMERG; break;
            default: break;
        }
        
        syslog(priority, "%s: %s (%s:%d in %s)",
               enhanced_error_level_to_string(context->level),
               context->message,
               context->file,
               context->line,
               context->function);
    }
}

/* Suggest recovery action */
error_recovery_t enhanced_error_suggest_recovery(const error_context_t *context) {
    if (!context) return ERROR_RECOVERY_NONE;
    
    switch (context->category) {
        case ERROR_CATEGORY_MEMORY:
            return ERROR_RECOVERY_RETRY;
        case ERROR_CATEGORY_FILE_IO:
            if (context->error_code == 2) { /* FILE_NOT_FOUND */
                return ERROR_RECOVERY_FALLBACK;
            }
            return ERROR_RECOVERY_RETRY;
        case ERROR_CATEGORY_NETWORK:
            return ERROR_RECOVERY_RETRY;
        case ERROR_CATEGORY_PARSER:
            return ERROR_RECOVERY_SKIP;
        case ERROR_CATEGORY_KERNEL:
            return ERROR_RECOVERY_ABORT;
        case ERROR_CATEGORY_PERMISSION:
            return ERROR_RECOVERY_ABORT;
        default:
            return ERROR_RECOVERY_NONE;
    }
}

/* Attempt error recovery */
int enhanced_error_attempt_recovery(error_recovery_t action, const error_context_t *context) {
    if (!context) return 0;
    
    pthread_mutex_lock(&error_state.mutex);
    error_state.stats.recovery_attempts++;
    pthread_mutex_unlock(&error_state.mutex);
    
    switch (action) {
        case ERROR_RECOVERY_RETRY:
            /* Sleep briefly and retry */
            usleep(100000); /* 100ms */
            break;
        case ERROR_RECOVERY_FALLBACK:
            /* Use fallback mechanism */
            break;
        case ERROR_RECOVERY_SKIP:
            /* Skip current operation */
            break;
        case ERROR_RECOVERY_ABORT:
            /* Abort operation */
            return 0;
        default:
            return 0;
    }
    
    pthread_mutex_lock(&error_state.mutex);
    error_state.stats.successful_recoveries++;
    pthread_mutex_unlock(&error_state.mutex);
    
    return 1;
}

/* Get error statistics */
error_stats_t *enhanced_error_get_stats(void) {
    if (!error_state.initialized) enhanced_error_init();
    return &error_state.stats;
}

/* Print error statistics */
void enhanced_error_print_stats(void) {
    error_stats_t *stats = enhanced_error_get_stats();
    if (!stats) return;
    
    printf("Error Statistics:\n");
    printf("  Total Errors: %lu\n", stats->total_errors);
    printf("  Recovery Attempts: %lu\n", stats->recovery_attempts);
    printf("  Successful Recoveries: %lu\n", stats->successful_recoveries);
    
    if (stats->total_errors > 0) {
        printf("  Recovery Rate: %.2f%%\n",
               (double)stats->successful_recoveries / stats->recovery_attempts * 100);
    }
    
    printf("  Errors by Level:\n");
    for (int i = 0; i < 6; i++) {
        if (stats->errors_by_level[i] > 0) {
            printf("    %s: %lu\n", enhanced_error_level_to_string(i), stats->errors_by_level[i]);
        }
    }
    
    printf("  Errors by Category:\n");
    for (int i = 0; i < 9; i++) {
        if (stats->errors_by_category[i] > 0) {
            printf("    %s: %lu\n", enhanced_error_category_to_string(i), stats->errors_by_category[i]);
        }
    }
}

/* Reset error statistics */
void enhanced_error_reset_stats(void) {
    if (!error_state.initialized) enhanced_error_init();
    
    pthread_mutex_lock(&error_state.mutex);
    memset(&error_state.stats, 0, sizeof(error_state.stats));
    error_state.stats.first_error = time(NULL);
    pthread_mutex_unlock(&error_state.mutex);
}

/* Convert error level to string */
const char *enhanced_error_level_to_string(error_level_t level) {
    static const char *levels[] = {
        "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "FATAL"
    };
    
    if (level >= 0 && level < 6) {
        return levels[level];
    }
    return "UNKNOWN";
}

/* Convert error category to string */
const char *enhanced_error_category_to_string(error_category_t category) {
    static const char *categories[] = {
        "MEMORY", "FILE_IO", "NETWORK", "PARSER", "KERNEL",
        "PERMISSION", "VALIDATION", "SYSTEM", "UNKNOWN"
    };
    
    if (category >= 0 && category < 9) {
        return categories[category];
    }
    return "UNKNOWN";
}

/* Convert error code to string */
const char *enhanced_error_code_to_string(uint32_t error_code) {
    if (error_code < sizeof(error_code_strings) / sizeof(error_code_strings[0])) {
        return error_code_strings[error_code];
    }
    return "UNKNOWN_ERROR_CODE";
}

/* Format error context to string */
void enhanced_error_format_context(char *buffer, size_t size, const error_context_t *context) {
    if (!buffer || !context || size == 0) return;
    
    snprintf(buffer, size,
             "[%s] %s: %s (%s:%d in %s) - Code: %u",
             enhanced_error_level_to_string(context->level),
             enhanced_error_category_to_string(context->category),
             context->message,
             context->file,
             context->line,
             context->function,
             context->error_code);
}

/* Memory-safe string functions */
char *enhanced_strdup(const char *str) {
    if (!str) return NULL;
    
    size_t len = strlen(str) + 1;
    char *copy = malloc(len);
    if (!copy) {
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for string duplication");
        return NULL;
    }
    
    memcpy(copy, str, len);
    return copy;
}

char *enhanced_strndup(const char *str, size_t n) {
    if (!str) return NULL;
    
    size_t len = strnlen(str, n);
    char *copy = malloc(len + 1);
    if (!copy) {
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for string duplication");
        return NULL;
    }
    
    memcpy(copy, str, len);
    copy[len] = '\0';
    return copy;
}

int enhanced_snprintf(char *str, size_t size, const char *format, ...) {
    if (!str || !format || size == 0) return -1;
    
    va_list args;
    va_start(args, format);
    int result = vsnprintf(str, size, format, args);
    va_end(args);
    
    if (result < 0) {
        ENHANCED_ERROR_FILE(10, "snprintf failed");
    } else if ((size_t)result >= size) {
        ENHANCED_WARNING(ERROR_CATEGORY_VALIDATION, 11, "String truncated in snprintf");
    }
    
    return result;
}

int enhanced_vsnprintf(char *str, size_t size, const char *format, va_list ap) {
    if (!str || !format || size == 0) return -1;
    
    int result = vsnprintf(str, size, format, ap);
    
    if (result < 0) {
        ENHANCED_ERROR_FILE(10, "vsnprintf failed");
    } else if ((size_t)result >= size) {
        ENHANCED_WARNING(ERROR_CATEGORY_VALIDATION, 11, "String truncated in vsnprintf");
    }
    
    return result;
}
