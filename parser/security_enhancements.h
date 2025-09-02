/*
 * Security Enhancements for AppArmor Parser
 * 
 * Provides additional security measures including input validation,
 * secure memory handling, and protection against common vulnerabilities.
 */

#ifndef SECURITY_ENHANCEMENTS_H
#define SECURITY_ENHANCEMENTS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Security validation levels */
typedef enum {
    SECURITY_LEVEL_STRICT = 0,
    SECURITY_LEVEL_MODERATE,
    SECURITY_LEVEL_PERMISSIVE
} security_level_t;

/* Input validation functions */
bool security_validate_path(const char *path, size_t max_length);
bool security_validate_profile_name(const char *name, size_t max_length);
bool security_validate_rule_content(const char *content, size_t max_length);
bool security_validate_file_extension(const char *filename, const char **allowed_extensions);

/* Secure string functions */
char *security_strdup(const char *str);
char *security_strndup(const char *str, size_t n);
int security_snprintf(char *str, size_t size, const char *format, ...);
int security_strcpy(char *dest, size_t dest_size, const char *src);
int security_strcat(char *dest, size_t dest_size, const char *src);

/* Memory protection */
void *security_malloc(size_t size);
void *security_calloc(size_t nmemb, size_t size);
void *security_realloc(void *ptr, size_t size);
void security_free(void *ptr);
void security_memset(void *ptr, int c, size_t size);
void security_memcpy(void *dest, const void *src, size_t size);

/* Buffer overflow protection */
bool security_check_buffer_bounds(const void *ptr, size_t size, size_t offset);
bool security_validate_buffer_access(const void *buffer, size_t buffer_size, 
                                    const void *access_ptr, size_t access_size);

/* Integer overflow protection */
bool security_check_add_overflow(size_t a, size_t b, size_t *result);
bool security_check_mul_overflow(size_t a, size_t b, size_t *result);
bool security_check_sub_overflow(size_t a, size_t b, size_t *result);

/* File system security */
bool security_validate_file_path(const char *path);
bool security_check_file_permissions(const char *path, int required_perms);
bool security_validate_directory_path(const char *path);
bool security_prevent_directory_traversal(const char *path);

/* Network security */
bool security_validate_ip_address(const char *ip);
bool security_validate_port_number(int port);
bool security_validate_domain_name(const char *domain);

/* Cryptographic helpers */
void security_generate_random_bytes(void *buffer, size_t size);
uint32_t security_generate_random_uint32(void);
bool security_constant_time_compare(const void *a, const void *b, size_t size);

/* Security configuration */
void security_set_level(security_level_t level);
security_level_t security_get_level(void);
void security_enable_protections(bool enable);
bool security_protections_enabled(void);

/* Audit and logging */
void security_log_violation(const char *function, const char *description);
void security_log_attempt(const char *function, const char *description);
void security_enable_audit_logging(bool enable);

/* Utility macros for secure operations */
#define SECURE_MALLOC(size) security_malloc(size)
#define SECURE_FREE(ptr) security_free(ptr)
#define SECURE_STRDUP(str) security_strdup(str)
#define SECURE_STRNCPY(dest, src, size) security_strcpy(dest, size, src)
#define SECURE_STRNCAT(dest, src, size) security_strcat(dest, size, src)

/* Validation macros */
#define VALIDATE_PATH(path) security_validate_path(path, PATH_MAX)
#define VALIDATE_PROFILE_NAME(name) security_validate_profile_name(name, 256)
#define VALIDATE_RULE_CONTENT(content) security_validate_rule_content(content, 4096)

/* Bounds checking macros */
#define CHECK_BOUNDS(ptr, size, offset) security_check_buffer_bounds(ptr, size, offset)
#define VALIDATE_ACCESS(buffer, buf_size, access_ptr, access_size) \
    security_validate_buffer_access(buffer, buf_size, access_ptr, access_size)

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_ENHANCEMENTS_H */
