/*
 * Security Enhancements Implementation for AppArmor Parser
 * 
 * Provides additional security measures including input validation,
 * secure memory handling, and protection against common vulnerabilities.
 */

#include "security_enhancements.h"
#include "enhanced_error.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <regex.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <pthread.h>

/* Global security state */
static struct {
    security_level_t level;
    bool protections_enabled;
    bool audit_logging_enabled;
    pthread_mutex_t mutex;
    int initialized;
} security_state = {0};

/* Initialize security enhancements */
static void security_init(void) {
    if (security_state.initialized) return;
    
    memset(&security_state, 0, sizeof(security_state));
    security_state.level = SECURITY_LEVEL_MODERATE;
    security_state.protections_enabled = true;
    security_state.audit_logging_enabled = false;
    
    if (pthread_mutex_init(&security_state.mutex, NULL) != 0) {
        fprintf(stderr, "Failed to initialize security mutex\n");
        return;
    }
    
    security_state.initialized = 1;
}

/* Input validation functions */
bool security_validate_path(const char *path, size_t max_length) {
    if (!path) return false;
    
    security_init();
    
    size_t len = strnlen(path, max_length);
    if (len == 0 || len >= max_length) return false;
    
    /* Check for directory traversal attempts */
    if (strstr(path, "../") || strstr(path, "..\\")) {
        security_log_violation("security_validate_path", "Directory traversal attempt detected");
        return false;
    }
    
    /* Check for null bytes */
    if (memchr(path, '\0', len) != path + len) {
        security_log_violation("security_validate_path", "Null byte injection attempt detected");
        return false;
    }
    
    /* Check for control characters */
    for (size_t i = 0; i < len; i++) {
        if (path[i] < 32 && path[i] != '\t' && path[i] != '\n' && path[i] != '\r') {
            security_log_violation("security_validate_path", "Control character in path detected");
            return false;
        }
    }
    
    return true;
}

bool security_validate_profile_name(const char *name, size_t max_length) {
    if (!name) return false;
    
    security_init();
    
    size_t len = strnlen(name, max_length);
    if (len == 0 || len >= max_length) return false;
    
    /* Profile names should only contain alphanumeric characters, hyphens, and underscores */
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || c == '-' || c == '_')) {
            security_log_violation("security_validate_profile_name", "Invalid character in profile name");
            return false;
        }
    }
    
    return true;
}

bool security_validate_rule_content(const char *content, size_t max_length) {
    if (!content) return false;
    
    security_init();
    
    size_t len = strnlen(content, max_length);
    if (len >= max_length) return false;
    
    /* Check for potential injection patterns */
    const char *dangerous_patterns[] = {
        "exec(",
        "system(",
        "popen(",
        "eval(",
        "script:",
        "include:",
        NULL
    };
    
    for (int i = 0; dangerous_patterns[i]; i++) {
        if (strstr(content, dangerous_patterns[i])) {
            security_log_violation("security_validate_rule_content", "Potentially dangerous pattern detected");
            return false;
        }
    }
    
    return true;
}

bool security_validate_file_extension(const char *filename, const char **allowed_extensions) {
    if (!filename || !allowed_extensions) return false;
    
    security_init();
    
    const char *ext = strrchr(filename, '.');
    if (!ext) return false;
    
    ext++; /* Skip the dot */
    
    for (int i = 0; allowed_extensions[i]; i++) {
        if (strcasecmp(ext, allowed_extensions[i]) == 0) {
            return true;
        }
    }
    
    security_log_violation("security_validate_file_extension", "File extension not in allowed list");
    return false;
}

/* Secure string functions */
char *security_strdup(const char *str) {
    if (!str) return NULL;
    
    security_init();
    
    size_t len = strlen(str) + 1;
    char *copy = security_malloc(len);
    if (copy) {
        memcpy(copy, str, len);
    }
    
    return copy;
}

char *security_strndup(const char *str, size_t n) {
    if (!str) return NULL;
    
    security_init();
    
    size_t len = strnlen(str, n);
    char *copy = security_malloc(len + 1);
    if (copy) {
        memcpy(copy, str, len);
        copy[len] = '\0';
    }
    
    return copy;
}

int security_snprintf(char *str, size_t size, const char *format, ...) {
    if (!str || !format || size == 0) return -1;
    
    security_init();
    
    va_list args;
    va_start(args, format);
    int result = vsnprintf(str, size, format, args);
    va_end(args);
    
    if (result < 0) {
        ENHANCED_ERROR_FILE(10, "security_snprintf failed");
    } else if ((size_t)result >= size) {
        ENHANCED_WARNING(ERROR_CATEGORY_VALIDATION, 11, "String truncated in security_snprintf");
        str[size - 1] = '\0'; /* Ensure null termination */
    }
    
    return result;
}

int security_strcpy(char *dest, size_t dest_size, const char *src) {
    if (!dest || !src || dest_size == 0) return -1;
    
    security_init();
    
    size_t src_len = strnlen(src, dest_size - 1);
    if (src_len >= dest_size) {
        security_log_violation("security_strcpy", "Buffer overflow attempt detected");
        return -1;
    }
    
    memcpy(dest, src, src_len);
    dest[src_len] = '\0';
    
    return 0;
}

int security_strcat(char *dest, size_t dest_size, const char *src) {
    if (!dest || !src || dest_size == 0) return -1;
    
    security_init();
    
    size_t dest_len = strnlen(dest, dest_size);
    size_t src_len = strnlen(src, dest_size - dest_len - 1);
    
    if (dest_len + src_len >= dest_size) {
        security_log_violation("security_strcat", "Buffer overflow attempt detected");
        return -1;
    }
    
    memcpy(dest + dest_len, src, src_len);
    dest[dest_len + src_len] = '\0';
    
    return 0;
}

/* Memory protection */
void *security_malloc(size_t size) {
    security_init();
    
    if (size == 0) return NULL;
    
    void *ptr = malloc(size);
    if (!ptr) {
        ENHANCED_ERROR_MEMORY(1, "Memory allocation failed: %zu bytes", size);
        return NULL;
    }
    
    /* Initialize memory to prevent information leakage */
    memset(ptr, 0, size);
    
    return ptr;
}

void *security_calloc(size_t nmemb, size_t size) {
    security_init();
    
    if (nmemb == 0 || size == 0) return NULL;
    
    /* Check for overflow */
    if (nmemb > SIZE_MAX / size) {
        ENHANCED_ERROR_MEMORY(1, "Integer overflow in security_calloc");
        return NULL;
    }
    
    void *ptr = calloc(nmemb, size);
    if (!ptr) {
        ENHANCED_ERROR_MEMORY(1, "Memory allocation failed: %zu * %zu bytes", nmemb, size);
        return NULL;
    }
    
    return ptr;
}

void *security_realloc(void *ptr, size_t size) {
    security_init();
    
    if (size == 0) {
        security_free(ptr);
        return NULL;
    }
    
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr && size > 0) {
        ENHANCED_ERROR_MEMORY(1, "Memory reallocation failed: %zu bytes", size);
        return NULL;
    }
    
    return new_ptr;
}

void security_free(void *ptr) {
    if (ptr) {
        /* Clear memory before freeing to prevent information leakage */
        memset(ptr, 0, sizeof(*ptr));
        free(ptr);
    }
}

void security_memset(void *ptr, int c, size_t size) {
    if (ptr && size > 0) {
        memset(ptr, c, size);
    }
}

void security_memcpy(void *dest, const void *src, size_t size) {
    if (dest && src && size > 0) {
        memcpy(dest, src, size);
    }
}

/* Buffer overflow protection */
bool security_check_buffer_bounds(const void *ptr, size_t size, size_t offset) {
    if (!ptr) return false;
    
    security_init();
    
    /* Check for potential overflow */
    if (offset > size) {
        security_log_violation("security_check_buffer_bounds", "Buffer bounds violation detected");
        return false;
    }
    
    return true;
}

bool security_validate_buffer_access(const void *buffer, size_t buffer_size, 
                                    const void *access_ptr, size_t access_size) {
    if (!buffer || !access_ptr) return false;
    
    security_init();
    
    /* Check if access pointer is within buffer bounds */
    if (access_ptr < buffer || access_ptr >= (char*)buffer + buffer_size) {
        security_log_violation("security_validate_buffer_access", "Buffer access out of bounds");
        return false;
    }
    
    /* Check if access would exceed buffer bounds */
    if ((char*)access_ptr + access_size > (char*)buffer + buffer_size) {
        security_log_violation("security_validate_buffer_access", "Buffer access would exceed bounds");
        return false;
    }
    
    return true;
}

/* Integer overflow protection */
bool security_check_add_overflow(size_t a, size_t b, size_t *result) {
    if (!result) return false;
    
    security_init();
    
    if (a > SIZE_MAX - b) {
        security_log_violation("security_check_add_overflow", "Integer overflow in addition");
        return false;
    }
    
    *result = a + b;
    return true;
}

bool security_check_mul_overflow(size_t a, size_t b, size_t *result) {
    if (!result) return false;
    
    security_init();
    
    if (a > 0 && b > SIZE_MAX / a) {
        security_log_violation("security_check_mul_overflow", "Integer overflow in multiplication");
        return false;
    }
    
    *result = a * b;
    return true;
}

bool security_check_sub_overflow(size_t a, size_t b, size_t *result) {
    if (!result) return false;
    
    security_init();
    
    if (a < b) {
        security_log_violation("security_check_sub_overflow", "Integer underflow in subtraction");
        return false;
    }
    
    *result = a - b;
    return true;
}

/* File system security */
bool security_validate_file_path(const char *path) {
    if (!path) return false;
    
    security_init();
    
    /* Check for absolute path */
    if (path[0] != '/') {
        security_log_violation("security_validate_file_path", "Relative path not allowed");
        return false;
    }
    
    /* Check for directory traversal */
    if (strstr(path, "../") || strstr(path, "..\\")) {
        security_log_violation("security_validate_file_path", "Directory traversal attempt");
        return false;
    }
    
    return true;
}

bool security_check_file_permissions(const char *path, int required_perms) {
    if (!path) return false;
    
    security_init();
    
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    
    /* Check if current user has required permissions */
    uid_t uid = getuid();
    gid_t gid = getgid();
    
    int file_perms = 0;
    if (st.st_uid == uid) {
        file_perms = (st.st_mode & S_IRWXU) >> 6;
    } else if (st.st_gid == gid) {
        file_perms = (st.st_mode & S_IRWXG) >> 3;
    } else {
        file_perms = st.st_mode & S_IRWXO;
    }
    
    return (file_perms & required_perms) == required_perms;
}

bool security_validate_directory_path(const char *path) {
    if (!security_validate_file_path(path)) return false;
    
    security_init();
    
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    
    return S_ISDIR(st.st_mode);
}

bool security_prevent_directory_traversal(const char *path) {
    if (!path) return false;
    
    security_init();
    
    /* Check for various directory traversal patterns */
    const char *patterns[] = {
        "../",
        "..\\",
        "/../",
        "\\..\\",
        "/..",
        "\\..",
        NULL
    };
    
    for (int i = 0; patterns[i]; i++) {
        if (strstr(path, patterns[i])) {
            security_log_violation("security_prevent_directory_traversal", "Directory traversal pattern detected");
            return false;
        }
    }
    
    return true;
}

/* Network security */
bool security_validate_ip_address(const char *ip) {
    if (!ip) return false;
    
    security_init();
    
    /* Simple IPv4 validation */
    int a, b, c, d;
    if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        return (a >= 0 && a <= 255 && b >= 0 && b <= 255 && 
                c >= 0 && c <= 255 && d >= 0 && d <= 255);
    }
    
    return false;
}

bool security_validate_port_number(int port) {
    security_init();
    
    return (port >= 1 && port <= 65535);
}

bool security_validate_domain_name(const char *domain) {
    if (!domain) return false;
    
    security_init();
    
    size_t len = strlen(domain);
    if (len == 0 || len > 253) return false;
    
    /* Check for valid characters */
    for (size_t i = 0; i < len; i++) {
        char c = domain[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || c == '-' || c == '.')) {
            return false;
        }
    }
    
    return true;
}

/* Cryptographic helpers */
void security_generate_random_bytes(void *buffer, size_t size) {
    if (!buffer || size == 0) return;
    
    security_init();
    
    if (RAND_bytes(buffer, size) != 1) {
        ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_SYSTEM, 1, "Failed to generate random bytes");
        /* Fallback to less secure method */
        for (size_t i = 0; i < size; i++) {
            ((unsigned char*)buffer)[i] = rand() % 256;
        }
    }
}

uint32_t security_generate_random_uint32(void) {
    uint32_t value;
    security_generate_random_bytes(&value, sizeof(value));
    return value;
}

bool security_constant_time_compare(const void *a, const void *b, size_t size) {
    if (!a || !b || size == 0) return false;
    
    security_init();
    
    const unsigned char *byte_a = (const unsigned char*)a;
    const unsigned char *byte_b = (const unsigned char*)b;
    
    unsigned char result = 0;
    for (size_t i = 0; i < size; i++) {
        result |= byte_a[i] ^ byte_b[i];
    }
    
    return result == 0;
}

/* Security configuration */
void security_set_level(security_level_t level) {
    security_init();
    
    pthread_mutex_lock(&security_state.mutex);
    security_state.level = level;
    pthread_mutex_unlock(&security_state.mutex);
}

security_level_t security_get_level(void) {
    security_init();
    
    pthread_mutex_lock(&security_state.mutex);
    security_level_t level = security_state.level;
    pthread_mutex_unlock(&security_state.mutex);
    
    return level;
}

void security_enable_protections(bool enable) {
    security_init();
    
    pthread_mutex_lock(&security_state.mutex);
    security_state.protections_enabled = enable;
    pthread_mutex_unlock(&security_state.mutex);
}

bool security_protections_enabled(void) {
    security_init();
    
    pthread_mutex_lock(&security_state.mutex);
    bool enabled = security_state.protections_enabled;
    pthread_mutex_unlock(&security_state.mutex);
    
    return enabled;
}

/* Audit and logging */
void security_log_violation(const char *function, const char *description) {
    if (!function || !description) return;
    
    security_init();
    
    if (security_state.audit_logging_enabled) {
        ENHANCED_ERROR(ERROR_LEVEL_WARNING, ERROR_CATEGORY_VALIDATION, 1, 
                      "Security violation in %s: %s", function, description);
    }
}

void security_log_attempt(const char *function, const char *description) {
    if (!function || !description) return;
    
    security_init();
    
    if (security_state.audit_logging_enabled) {
        ENHANCED_INFO(ERROR_CATEGORY_VALIDATION, 1, "Security attempt in %s: %s", function, description);
    }
}

void security_enable_audit_logging(bool enable) {
    security_init();
    
    pthread_mutex_lock(&security_state.mutex);
    security_state.audit_logging_enabled = enable;
    pthread_mutex_unlock(&security_state.mutex);
}
