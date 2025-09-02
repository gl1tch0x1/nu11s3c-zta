/*
 * Binary Profile Serialization for AppArmor Parser
 * 
 * Provides serialization and deserialization of AppArmor profiles
 * to/from binary format for fast loading and caching.
 */

#ifndef BINARY_PROFILE_SERIALIZATION_H
#define BINARY_PROFILE_SERIALIZATION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Binary profile header */
typedef struct {
    uint32_t magic;           /* Magic number: 0x41415042 ("AAPB") */
    uint32_t version;         /* Binary format version */
    uint32_t header_size;     /* Size of this header */
    uint32_t profile_size;    /* Total size of profile data */
    uint32_t checksum;        /* CRC32 checksum of profile data */
    uint64_t timestamp;       /* Creation timestamp */
    uint32_t flags;           /* Profile flags */
    char profile_name[256];   /* Profile name */
    char compiler_version[64]; /* Parser version that created this */
} binary_profile_header_t;

/* Binary profile section types */
typedef enum {
    BINARY_SECTION_HEADER = 0,
    BINARY_SECTION_PROFILE_INFO,
    BINARY_SECTION_FILE_RULES,
    BINARY_SECTION_NETWORK_RULES,
    BINARY_SECTION_CAPABILITY_RULES,
    BINARY_SECTION_MOUNT_RULES,
    BINARY_SECTION_PTRACE_RULES,
    BINARY_SECTION_SIGNAL_RULES,
    BINARY_SECTION_DBUS_RULES,
    BINARY_SECTION_RLIMIT_RULES,
    BINARY_SECTION_CONDITIONS,
    BINARY_SECTION_VARIABLES,
    BINARY_SECTION_INCLUDES,
    BINARY_SECTION_ABI,
    BINARY_SECTION_END = 0xFFFFFFFF
} binary_section_type_t;

/* Binary section header */
typedef struct {
    uint32_t type;            /* Section type */
    uint32_t size;            /* Section size (excluding this header) */
    uint32_t offset;          /* Offset from start of profile */
    uint32_t checksum;        /* CRC32 checksum of section data */
} binary_section_header_t;

/* Binary profile structure */
typedef struct {
    binary_profile_header_t header;
    binary_section_header_t *sections;
    uint32_t section_count;
    void *data;               /* Raw profile data */
    size_t data_size;
} binary_profile_t;

/* Serialization options */
typedef struct {
    bool compress;            /* Enable compression */
    bool encrypt;             /* Enable encryption */
    bool include_debug;       /* Include debug information */
    bool optimize;            /* Optimize for size */
    uint32_t compression_level; /* Compression level (1-9) */
    char *encryption_key;     /* Encryption key (if encrypt=true) */
} serialization_options_t;

/* Function prototypes */
binary_profile_t *binary_profile_create(const char *profile_name);
void binary_profile_destroy(binary_profile_t *profile);
int binary_profile_serialize(binary_profile_t *profile, 
                            const void *profile_data, 
                            size_t profile_size,
                            const serialization_options_t *options);
int binary_profile_deserialize(const void *binary_data, 
                              size_t binary_size,
                              binary_profile_t **profile);
int binary_profile_validate(const binary_profile_t *profile);
int binary_profile_verify_checksum(const binary_profile_t *profile);

/* File I/O functions */
int binary_profile_save(const binary_profile_t *profile, const char *filename);
int binary_profile_load(const char *filename, binary_profile_t **profile);
int binary_profile_save_to_fd(const binary_profile_t *profile, int fd);
int binary_profile_load_from_fd(int fd, binary_profile_t **profile);

/* Section management */
int binary_profile_add_section(binary_profile_t *profile,
                              binary_section_type_t type,
                              const void *data,
                              size_t size);
int binary_profile_get_section(const binary_profile_t *profile,
                              binary_section_type_t type,
                              void **data,
                              size_t *size);
int binary_profile_remove_section(binary_profile_t *profile, binary_section_type_t type);

/* Compression and encryption */
int binary_profile_compress(binary_profile_t *profile, uint32_t level);
int binary_profile_decompress(binary_profile_t *profile);
int binary_profile_encrypt(binary_profile_t *profile, const char *key);
int binary_profile_decrypt(binary_profile_t *profile, const char *key);

/* Utility functions */
uint32_t binary_profile_calculate_checksum(const void *data, size_t size);
bool binary_profile_is_valid_magic(uint32_t magic);
const char *binary_profile_version_to_string(uint32_t version);
const char *binary_section_type_to_string(binary_section_type_t type);

/* Profile conversion functions */
int binary_profile_from_text(const char *text_profile, 
                            const char *profile_name,
                            binary_profile_t **binary_profile);
int binary_profile_to_text(const binary_profile_t *binary_profile,
                          char **text_profile);

/* Cache integration */
typedef struct {
    char *cache_dir;
    size_t max_cache_size;
    time_t cache_ttl;
    bool enable_compression;
    bool enable_encryption;
} binary_cache_config_t;

int binary_profile_cache_init(const binary_cache_config_t *config);
void binary_profile_cache_cleanup(void);
int binary_profile_cache_put(const char *profile_name, const binary_profile_t *profile);
int binary_profile_cache_get(const char *profile_name, binary_profile_t **profile);
int binary_profile_cache_remove(const char *profile_name);
int binary_profile_cache_clear(void);
bool binary_profile_cache_exists(const char *profile_name);

/* Performance monitoring */
typedef struct {
    uint64_t serialization_time_us;
    uint64_t deserialization_time_us;
    uint64_t compression_time_us;
    uint64_t decompression_time_us;
    size_t original_size;
    size_t compressed_size;
    double compression_ratio;
    uint64_t cache_hits;
    uint64_t cache_misses;
} binary_profile_stats_t;

binary_profile_stats_t *binary_profile_get_stats(void);
void binary_profile_print_stats(const binary_profile_stats_t *stats);
void binary_profile_reset_stats(void);

/* Error handling */
typedef enum {
    BINARY_PROFILE_SUCCESS = 0,
    BINARY_PROFILE_ERROR_INVALID_MAGIC,
    BINARY_PROFILE_ERROR_INVALID_VERSION,
    BINARY_PROFILE_ERROR_CHECKSUM_MISMATCH,
    BINARY_PROFILE_ERROR_CORRUPTED_DATA,
    BINARY_PROFILE_ERROR_INSUFFICIENT_MEMORY,
    BINARY_PROFILE_ERROR_IO_ERROR,
    BINARY_PROFILE_ERROR_INVALID_FORMAT,
    BINARY_PROFILE_ERROR_ENCRYPTION_FAILED,
    BINARY_PROFILE_ERROR_DECRYPTION_FAILED,
    BINARY_PROFILE_ERROR_COMPRESSION_FAILED,
    BINARY_PROFILE_ERROR_DECOMPRESSION_FAILED
} binary_profile_error_t;

const char *binary_profile_error_to_string(binary_profile_error_t error);

/* Default options */
serialization_options_t *binary_profile_default_options(void);
binary_cache_config_t *binary_profile_default_cache_config(void);

/* Macro for profile version */
#define BINARY_PROFILE_VERSION_MAJOR 1
#define BINARY_PROFILE_VERSION_MINOR 0
#define BINARY_PROFILE_VERSION_PATCH 0
#define BINARY_PROFILE_VERSION ((BINARY_PROFILE_VERSION_MAJOR << 16) | \
                               (BINARY_PROFILE_VERSION_MINOR << 8) | \
                               BINARY_PROFILE_VERSION_PATCH)

/* Magic number for binary profiles */
#define BINARY_PROFILE_MAGIC 0x41415042  /* "AAPB" */

#ifdef __cplusplus
}
#endif

#endif /* BINARY_PROFILE_SERIALIZATION_H */
