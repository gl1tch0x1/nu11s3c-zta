/*
 * Enhanced Error Handling System for AppArmor Parser
 * 
 * Provides comprehensive error handling with context, recovery mechanisms,
 * and detailed logging for better debugging and user experience.
 */

#ifndef ENHANCED_ERROR_H
#define ENHANCED_ERROR_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error severity levels */
typedef enum {
    ERROR_LEVEL_DEBUG = 0,
    ERROR_LEVEL_INFO,
    ERROR_LEVEL_WARNING,
    ERROR_LEVEL_ERROR,
    ERROR_LEVEL_CRITICAL,
    ERROR_LEVEL_FATAL
} error_level_t;

/* Error categories */
typedef enum {
    ERROR_CATEGORY_MEMORY = 0,
    ERROR_CATEGORY_FILE_IO,
    ERROR_CATEGORY_NETWORK,
    ERROR_CATEGORY_PARSER,
    ERROR_CATEGORY_KERNEL,
    ERROR_CATEGORY_PERMISSION,
    ERROR_CATEGORY_VALIDATION,
    ERROR_CATEGORY_SYSTEM,
    ERROR_CATEGORY_UNKNOWN
} error_category_t;

/* Error context information */
typedef struct {
    const char *file;
    int line;
    const char *function;
    const char *component;
    time_t timestamp;
    uint32_t error_code;
    error_level_t level;
    error_category_t category;
    char *message;
    char *details;
    char *suggestion;
    void *user_data;
} error_context_t;

/* Error handler function type */
typedef void (*error_handler_t)(const error_context_t *context);

/* Error recovery action */
typedef enum {
    ERROR_RECOVERY_NONE = 0,
    ERROR_RECOVERY_RETRY,
    ERROR_RECOVERY_FALLBACK,
    ERROR_RECOVERY_SKIP,
    ERROR_RECOVERY_ABORT
} error_recovery_t;

/* Error statistics */
typedef struct {
    uint64_t total_errors;
    uint64_t errors_by_level[6];
    uint64_t errors_by_category[9];
    uint64_t recovery_attempts;
    uint64_t successful_recoveries;
    time_t first_error;
    time_t last_error;
} error_stats_t;

/* Function prototypes */
void enhanced_error_init(void);
void enhanced_error_cleanup(void);
void enhanced_error_set_handler(error_handler_t handler);
void enhanced_error_set_level(error_level_t min_level);
void enhanced_error_set_log_file(const char *filename);

/* Main error reporting functions */
void enhanced_error_report(error_level_t level, error_category_t category,
                          const char *file, int line, const char *function,
                          uint32_t error_code, const char *format, ...);

void enhanced_error_report_with_context(error_level_t level, error_category_t category,
                                       const char *file, int line, const char *function,
                                       uint32_t error_code, const char *message,
                                       const char *details, const char *suggestion);

/* Convenience macros */
#define ENHANCED_ERROR(level, category, code, ...) \
    enhanced_error_report(level, category, __FILE__, __LINE__, __FUNCTION__, code, __VA_ARGS__)

#define ENHANCED_ERROR_MEMORY(code, ...) \
    ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_MEMORY, code, __VA_ARGS__)

#define ENHANCED_ERROR_FILE(code, ...) \
    ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_FILE_IO, code, __VA_ARGS__)

#define ENHANCED_ERROR_PARSER(code, ...) \
    ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_PARSER, code, __VA_ARGS__)

#define ENHANCED_ERROR_KERNEL(code, ...) \
    ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_KERNEL, code, __VA_ARGS__)

#define ENHANCED_WARNING(category, code, ...) \
    ENHANCED_ERROR(ERROR_LEVEL_WARNING, category, code, __VA_ARGS__)

#define ENHANCED_INFO(category, code, ...) \
    ENHANCED_ERROR(ERROR_LEVEL_INFO, category, code, __VA_ARGS__)

#define ENHANCED_DEBUG(category, code, ...) \
    ENHANCED_ERROR(ERROR_LEVEL_DEBUG, category, code, __VA_ARGS__)

/* Error recovery functions */
error_recovery_t enhanced_error_suggest_recovery(const error_context_t *context);
int enhanced_error_attempt_recovery(error_recovery_t action, const error_context_t *context);

/* Statistics and monitoring */
error_stats_t *enhanced_error_get_stats(void);
void enhanced_error_print_stats(void);
void enhanced_error_reset_stats(void);

/* Utility functions */
const char *enhanced_error_level_to_string(error_level_t level);
const char *enhanced_error_category_to_string(error_category_t category);
const char *enhanced_error_code_to_string(uint32_t error_code);
void enhanced_error_format_context(char *buffer, size_t size, const error_context_t *context);

/* Memory-safe string functions */
char *enhanced_strdup(const char *str);
char *enhanced_strndup(const char *str, size_t n);
int enhanced_snprintf(char *str, size_t size, const char *format, ...);
int enhanced_vsnprintf(char *str, size_t size, const char *format, va_list ap);

#ifdef __cplusplus
}
#endif

#endif /* ENHANCED_ERROR_H */
