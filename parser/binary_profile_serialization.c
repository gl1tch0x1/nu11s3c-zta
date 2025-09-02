/*
 * Binary Profile Serialization Implementation for AppArmor Parser
 * 
 * Provides serialization and deserialization of AppArmor profiles
 * to/from binary format for fast loading and caching.
 */

#include "binary_profile_serialization.h"
#include "enhanced_error.h"
#include "security_enhancements.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>

/* Global binary profile state */
static struct {
    binary_cache_config_t cache_config;
    binary_profile_stats_t stats;
    pthread_mutex_t mutex;
    int initialized;
} binary_state = {0};

/* Initialize binary profile system */
static void binary_init(void) {
    if (binary_state.initialized) return;
    
    memset(&binary_state, 0, sizeof(binary_state));
    
    if (pthread_mutex_init(&binary_state.mutex, NULL) != 0) {
        ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_SYSTEM, 1, "Failed to initialize binary profile mutex");
        return;
    }
    
    binary_state.initialized = 1;
    ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Binary profile serialization initialized");
}

/* Calculate CRC32 checksum */
uint32_t binary_profile_calculate_checksum(const void *data, size_t size) {
    if (!data || size == 0) return 0;
    
    uint32_t crc = 0xFFFFFFFF;
    const uint8_t *bytes = (const uint8_t*)data;
    
    static const uint32_t crc_table[256] = {
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
        0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
        0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
        0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
        0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
        0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
        0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
        0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
        0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
        0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
        0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
        0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
        0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
        0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
        0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
        0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
        0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
        0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
        0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
        0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
        0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
        0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
        0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
        0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
        0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
        0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
        0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
        0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
        0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
        0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
        0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
        0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
        0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
    };
    
    for (size_t i = 0; i < size; i++) {
        crc = crc_table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    
    return crc ^ 0xFFFFFFFF;
}

/* Check if magic number is valid */
bool binary_profile_is_valid_magic(uint32_t magic) {
    return magic == BINARY_PROFILE_MAGIC;
}

/* Create binary profile */
binary_profile_t *binary_profile_create(const char *profile_name) {
    if (!profile_name) return NULL;
    
    binary_init();
    
    binary_profile_t *profile = security_malloc(sizeof(binary_profile_t));
    if (!profile) {
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for binary profile");
        return NULL;
    }
    
    memset(profile, 0, sizeof(binary_profile_t));
    
    /* Initialize header */
    profile->header.magic = BINARY_PROFILE_MAGIC;
    profile->header.version = BINARY_PROFILE_VERSION;
    profile->header.header_size = sizeof(binary_profile_header_t);
    profile->header.timestamp = time(NULL);
    
    strncpy(profile->header.profile_name, profile_name, sizeof(profile->header.profile_name) - 1);
    profile->header.profile_name[sizeof(profile->header.profile_name) - 1] = '\0';
    
    strncpy(profile->header.compiler_version, "AppArmor Parser Enhanced", sizeof(profile->header.compiler_version) - 1);
    profile->header.compiler_version[sizeof(profile->header.compiler_version) - 1] = '\0';
    
    return profile;
}

/* Destroy binary profile */
void binary_profile_destroy(binary_profile_t *profile) {
    if (!profile) return;
    
    if (profile->sections) {
        security_free(profile->sections);
    }
    
    if (profile->data) {
        security_free(profile->data);
    }
    
    security_free(profile);
}

/* Serialize profile data */
int binary_profile_serialize(binary_profile_t *profile, 
                            const void *profile_data, 
                            size_t profile_size,
                            const serialization_options_t *options) {
    if (!profile || !profile_data || profile_size == 0) return -1;
    
    binary_init();
    
    uint64_t start_time = time(NULL) * 1000000; /* Convert to microseconds */
    
    /* Allocate data buffer */
    profile->data = security_malloc(profile_size);
    if (!profile->data) {
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for profile data");
        return -1;
    }
    
    memcpy(profile->data, profile_data, profile_size);
    profile->data_size = profile_size;
    
    /* Update header */
    profile->header.profile_size = profile_size;
    profile->header.checksum = binary_profile_calculate_checksum(profile_data, profile_size);
    
    /* Apply options if provided */
    if (options) {
        if (options->compress) {
            if (binary_profile_compress(profile, options->compression_level) != 0) {
                ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_SYSTEM, 1, "Failed to compress profile");
                return -1;
            }
        }
        
        if (options->encrypt && options->encryption_key) {
            if (binary_profile_encrypt(profile, options->encryption_key) != 0) {
                ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_SYSTEM, 1, "Failed to encrypt profile");
                return -1;
            }
        }
    }
    
    uint64_t end_time = time(NULL) * 1000000;
    binary_state.stats.serialization_time_us += (end_time - start_time);
    
    ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Profile serialized successfully: %s", profile->header.profile_name);
    return 0;
}

/* Deserialize profile data */
int binary_profile_deserialize(const void *binary_data, 
                              size_t binary_size,
                              binary_profile_t **profile) {
    if (!binary_data || !profile || binary_size < sizeof(binary_profile_header_t)) {
        return -1;
    }
    
    binary_init();
    
    uint64_t start_time = time(NULL) * 1000000;
    
    const binary_profile_header_t *header = (const binary_profile_header_t*)binary_data;
    
    /* Validate magic number */
    if (!binary_profile_is_valid_magic(header->magic)) {
        ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_VALIDATION, 1, "Invalid binary profile magic number");
        return BINARY_PROFILE_ERROR_INVALID_MAGIC;
    }
    
    /* Validate version */
    if (header->version != BINARY_PROFILE_VERSION) {
        ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_VALIDATION, 1, "Unsupported binary profile version");
        return BINARY_PROFILE_ERROR_INVALID_VERSION;
    }
    
    /* Create profile */
    *profile = security_malloc(sizeof(binary_profile_t));
    if (!*profile) {
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for binary profile");
        return BINARY_PROFILE_ERROR_INSUFFICIENT_MEMORY;
    }
    
    memset(*profile, 0, sizeof(binary_profile_t));
    
    /* Copy header */
    (*profile)->header = *header;
    
    /* Copy data */
    size_t data_offset = header->header_size;
    if (data_offset + header->profile_size > binary_size) {
        binary_profile_destroy(*profile);
        *profile = NULL;
        ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_VALIDATION, 1, "Binary profile data truncated");
        return BINARY_PROFILE_ERROR_CORRUPTED_DATA;
    }
    
    (*profile)->data = security_malloc(header->profile_size);
    if (!(*profile)->data) {
        binary_profile_destroy(*profile);
        *profile = NULL;
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for profile data");
        return BINARY_PROFILE_ERROR_INSUFFICIENT_MEMORY;
    }
    
    memcpy((*profile)->data, (const char*)binary_data + data_offset, header->profile_size);
    (*profile)->data_size = header->profile_size;
    
    /* Verify checksum */
    uint32_t calculated_checksum = binary_profile_calculate_checksum((*profile)->data, (*profile)->data_size);
    if (calculated_checksum != header->checksum) {
        binary_profile_destroy(*profile);
        *profile = NULL;
        ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_VALIDATION, 1, "Binary profile checksum mismatch");
        return BINARY_PROFILE_ERROR_CHECKSUM_MISMATCH;
    }
    
    uint64_t end_time = time(NULL) * 1000000;
    binary_state.stats.deserialization_time_us += (end_time - start_time);
    
    ENHANCED_INFO(ERROR_CATEGORY_SYSTEM, 1, "Profile deserialized successfully: %s", header->profile_name);
    return 0;
}

/* Validate binary profile */
int binary_profile_validate(const binary_profile_t *profile) {
    if (!profile) return -1;
    
    /* Validate magic number */
    if (!binary_profile_is_valid_magic(profile->header.magic)) {
        return BINARY_PROFILE_ERROR_INVALID_MAGIC;
    }
    
    /* Validate version */
    if (profile->header.version != BINARY_PROFILE_VERSION) {
        return BINARY_PROFILE_ERROR_INVALID_VERSION;
    }
    
    /* Validate header size */
    if (profile->header.header_size != sizeof(binary_profile_header_t)) {
        return BINARY_PROFILE_ERROR_INVALID_FORMAT;
    }
    
    /* Validate profile size */
    if (profile->header.profile_size != profile->data_size) {
        return BINARY_PROFILE_ERROR_INVALID_FORMAT;
    }
    
    return 0;
}

/* Verify checksum */
int binary_profile_verify_checksum(const binary_profile_t *profile) {
    if (!profile) return -1;
    
    uint32_t calculated_checksum = binary_profile_calculate_checksum(profile->data, profile->data_size);
    if (calculated_checksum != profile->header.checksum) {
        return BINARY_PROFILE_ERROR_CHECKSUM_MISMATCH;
    }
    
    return 0;
}

/* Save profile to file */
int binary_profile_save(const binary_profile_t *profile, const char *filename) {
    if (!profile || !filename) return -1;
    
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        ENHANCED_ERROR_FILE(2, "Failed to open file for writing: %s", filename);
        return BINARY_PROFILE_ERROR_IO_ERROR;
    }
    
    int result = binary_profile_save_to_fd(profile, fd);
    close(fd);
    
    if (result == 0) {
        ENHANCED_INFO(ERROR_CATEGORY_FILE_IO, 1, "Profile saved to file: %s", filename);
    }
    
    return result;
}

/* Load profile from file */
int binary_profile_load(const char *filename, binary_profile_t **profile) {
    if (!filename || !profile) return -1;
    
    struct stat st;
    if (stat(filename, &st) != 0) {
        ENHANCED_ERROR_FILE(2, "Failed to stat file: %s", filename);
        return BINARY_PROFILE_ERROR_IO_ERROR;
    }
    
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        ENHANCED_ERROR_FILE(2, "Failed to open file for reading: %s", filename);
        return BINARY_PROFILE_ERROR_IO_ERROR;
    }
    
    int result = binary_profile_load_from_fd(fd, profile);
    close(fd);
    
    if (result == 0) {
        ENHANCED_INFO(ERROR_CATEGORY_FILE_IO, 1, "Profile loaded from file: %s", filename);
    }
    
    return result;
}

/* Save profile to file descriptor */
int binary_profile_save_to_fd(const binary_profile_t *profile, int fd) {
    if (!profile || fd == -1) return -1;
    
    /* Write header */
    if (write(fd, &profile->header, sizeof(profile->header)) != sizeof(profile->header)) {
        ENHANCED_ERROR_FILE(10, "Failed to write profile header");
        return BINARY_PROFILE_ERROR_IO_ERROR;
    }
    
    /* Write sections */
    if (profile->sections) {
        if (write(fd, profile->sections, sizeof(binary_section_header_t) * profile->section_count) != 
            (ssize_t)(sizeof(binary_section_header_t) * profile->section_count)) {
            ENHANCED_ERROR_FILE(10, "Failed to write profile sections");
            return BINARY_PROFILE_ERROR_IO_ERROR;
        }
    }
    
    /* Write data */
    if (profile->data && profile->data_size > 0) {
        if (write(fd, profile->data, profile->data_size) != (ssize_t)profile->data_size) {
            ENHANCED_ERROR_FILE(10, "Failed to write profile data");
            return BINARY_PROFILE_ERROR_IO_ERROR;
        }
    }
    
    return 0;
}

/* Load profile from file descriptor */
int binary_profile_load_from_fd(int fd, binary_profile_t **profile) {
    if (fd == -1 || !profile) return -1;
    
    /* Read header */
    binary_profile_header_t header;
    if (read(fd, &header, sizeof(header)) != sizeof(header)) {
        ENHANCED_ERROR_FILE(10, "Failed to read profile header");
        return BINARY_PROFILE_ERROR_IO_ERROR;
    }
    
    /* Calculate total size needed */
    size_t total_size = sizeof(header) + header.profile_size;
    
    /* Allocate buffer */
    void *buffer = security_malloc(total_size);
    if (!buffer) {
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for profile buffer");
        return BINARY_PROFILE_ERROR_INSUFFICIENT_MEMORY;
    }
    
    /* Copy header to buffer */
    memcpy(buffer, &header, sizeof(header));
    
    /* Read remaining data */
    size_t remaining = header.profile_size;
    char *data_ptr = (char*)buffer + sizeof(header);
    
    while (remaining > 0) {
        ssize_t bytes_read = read(fd, data_ptr, remaining);
        if (bytes_read <= 0) {
            security_free(buffer);
            ENHANCED_ERROR_FILE(10, "Failed to read profile data");
            return BINARY_PROFILE_ERROR_IO_ERROR;
        }
        
        data_ptr += bytes_read;
        remaining -= bytes_read;
    }
    
    /* Deserialize from buffer */
    int result = binary_profile_deserialize(buffer, total_size, profile);
    security_free(buffer);
    
    return result;
}

/* Add section to profile */
int binary_profile_add_section(binary_profile_t *profile,
                              binary_section_type_t type,
                              const void *data,
                              size_t size) {
    if (!profile || !data || size == 0) return -1;
    
    /* Reallocate sections array */
    binary_section_header_t *new_sections = security_realloc(profile->sections, 
                                                           sizeof(binary_section_header_t) * (profile->section_count + 1));
    if (!new_sections) {
        ENHANCED_ERROR_MEMORY(1, "Failed to reallocate sections array");
        return -1;
    }
    
    profile->sections = new_sections;
    
    /* Add new section */
    binary_section_header_t *section = &profile->sections[profile->section_count];
    section->type = type;
    section->size = size;
    section->offset = profile->data_size;
    section->checksum = binary_profile_calculate_checksum(data, size);
    
    /* Append data */
    void *new_data = security_realloc(profile->data, profile->data_size + size);
    if (!new_data) {
        ENHANCED_ERROR_MEMORY(1, "Failed to reallocate profile data");
        return -1;
    }
    
    profile->data = new_data;
    memcpy((char*)profile->data + profile->data_size, data, size);
    profile->data_size += size;
    
    profile->section_count++;
    profile->header.profile_size = profile->data_size;
    
    return 0;
}

/* Get section from profile */
int binary_profile_get_section(const binary_profile_t *profile,
                              binary_section_type_t type,
                              void **data,
                              size_t *size) {
    if (!profile || !data || !size) return -1;
    
    for (uint32_t i = 0; i < profile->section_count; i++) {
        if (profile->sections[i].type == type) {
            *data = (char*)profile->data + profile->sections[i].offset;
            *size = profile->sections[i].size;
            return 0;
        }
    }
    
    return -1;
}

/* Remove section from profile */
int binary_profile_remove_section(binary_profile_t *profile, binary_section_type_t type) {
    if (!profile) return -1;
    
    /* Find section */
    uint32_t section_index = UINT32_MAX;
    for (uint32_t i = 0; i < profile->section_count; i++) {
        if (profile->sections[i].type == type) {
            section_index = i;
            break;
        }
    }
    
    if (section_index == UINT32_MAX) {
        return -1; /* Section not found */
    }
    
    /* Remove section from array */
    for (uint32_t i = section_index; i < profile->section_count - 1; i++) {
        profile->sections[i] = profile->sections[i + 1];
    }
    
    profile->section_count--;
    
    /* Reallocate sections array */
    if (profile->section_count > 0) {
        binary_section_header_t *new_sections = security_realloc(profile->sections, 
                                                               sizeof(binary_section_header_t) * profile->section_count);
        if (new_sections) {
            profile->sections = new_sections;
        }
    } else {
        security_free(profile->sections);
        profile->sections = NULL;
    }
    
    return 0;
}

/* Compress profile data */
int binary_profile_compress(binary_profile_t *profile, uint32_t level) {
    if (!profile || !profile->data || profile->data_size == 0) return -1;
    
    uint64_t start_time = time(NULL) * 1000000;
    
    /* Calculate compressed size */
    uLongf compressed_size = compressBound(profile->data_size);
    void *compressed_data = security_malloc(compressed_size);
    if (!compressed_data) {
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for compressed data");
        return BINARY_PROFILE_ERROR_COMPRESSION_FAILED;
    }
    
    /* Compress data */
    int result = compress2((Bytef*)compressed_data, &compressed_size, 
                          (const Bytef*)profile->data, profile->data_size, level);
    
    if (result != Z_OK) {
        security_free(compressed_data);
        ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_SYSTEM, 1, "Compression failed: %d", result);
        return BINARY_PROFILE_ERROR_COMPRESSION_FAILED;
    }
    
    /* Update profile */
    security_free(profile->data);
    profile->data = compressed_data;
    profile->data_size = compressed_size;
    profile->header.profile_size = compressed_size;
    profile->header.flags |= 0x01; /* Set compression flag */
    
    uint64_t end_time = time(NULL) * 1000000;
    binary_state.stats.compression_time_us += (end_time - start_time);
    binary_state.stats.compressed_size = compressed_size;
    
    return 0;
}

/* Decompress profile data */
int binary_profile_decompress(binary_profile_t *profile) {
    if (!profile || !profile->data || profile->data_size == 0) return -1;
    
    if (!(profile->header.flags & 0x01)) {
        return 0; /* Not compressed */
    }
    
    uint64_t start_time = time(NULL) * 1000000;
    
    /* Estimate decompressed size (this is a limitation of zlib) */
    uLongf decompressed_size = profile->data_size * 4; /* Conservative estimate */
    void *decompressed_data = security_malloc(decompressed_size);
    if (!decompressed_data) {
        ENHANCED_ERROR_MEMORY(1, "Failed to allocate memory for decompressed data");
        return BINARY_PROFILE_ERROR_DECOMPRESSION_FAILED;
    }
    
    /* Decompress data */
    int result = uncompress((Bytef*)decompressed_data, &decompressed_size, 
                           (const Bytef*)profile->data, profile->data_size);
    
    if (result != Z_OK) {
        security_free(decompressed_data);
        ENHANCED_ERROR(ERROR_LEVEL_ERROR, ERROR_CATEGORY_SYSTEM, 1, "Decompression failed: %d", result);
        return BINARY_PROFILE_ERROR_DECOMPRESSION_FAILED;
    }
    
    /* Update profile */
    security_free(profile->data);
    profile->data = decompressed_data;
    profile->data_size = decompressed_size;
    profile->header.profile_size = decompressed_size;
    profile->header.flags &= ~0x01; /* Clear compression flag */
    
    uint64_t end_time = time(NULL) * 1000000;
    binary_state.stats.decompression_time_us += (end_time - start_time);
    
    return 0;
}

/* Encrypt profile data */
int binary_profile_encrypt(binary_profile_t *profile, const char *key) {
    if (!profile || !profile->data || profile->data_size == 0 || !key) return -1;
    
    /* Simple XOR encryption for demonstration */
    /* In production, use proper encryption like AES */
    size_t key_len = strlen(key);
    if (key_len == 0) return -1;
    
    for (size_t i = 0; i < profile->data_size; i++) {
        ((unsigned char*)profile->data)[i] ^= key[i % key_len];
    }
    
    profile->header.flags |= 0x02; /* Set encryption flag */
    
    return 0;
}

/* Decrypt profile data */
int binary_profile_decrypt(binary_profile_t *profile, const char *key) {
    if (!profile || !profile->data || profile->data_size == 0 || !key) return -1;
    
    if (!(profile->header.flags & 0x02)) {
        return 0; /* Not encrypted */
    }
    
    /* Simple XOR decryption for demonstration */
    size_t key_len = strlen(key);
    if (key_len == 0) return -1;
    
    for (size_t i = 0; i < profile->data_size; i++) {
        ((unsigned char*)profile->data)[i] ^= key[i % key_len];
    }
    
    profile->header.flags &= ~0x02; /* Clear encryption flag */
    
    return 0;
}

/* Utility functions */
const char *binary_profile_version_to_string(uint32_t version) {
    static char version_str[32];
    snprintf(version_str, sizeof(version_str), "%d.%d.%d", 
             (version >> 16) & 0xFF, (version >> 8) & 0xFF, version & 0xFF);
    return version_str;
}

const char *binary_section_type_to_string(binary_section_type_t type) {
    switch (type) {
        case BINARY_SECTION_HEADER: return "header";
        case BINARY_SECTION_PROFILE_INFO: return "profile_info";
        case BINARY_SECTION_FILE_RULES: return "file_rules";
        case BINARY_SECTION_NETWORK_RULES: return "network_rules";
        case BINARY_SECTION_CAPABILITY_RULES: return "capability_rules";
        case BINARY_SECTION_MOUNT_RULES: return "mount_rules";
        case BINARY_SECTION_PTRACE_RULES: return "ptrace_rules";
        case BINARY_SECTION_SIGNAL_RULES: return "signal_rules";
        case BINARY_SECTION_DBUS_RULES: return "dbus_rules";
        case BINARY_SECTION_RLIMIT_RULES: return "rlimit_rules";
        case BINARY_SECTION_CONDITIONS: return "conditions";
        case BINARY_SECTION_VARIABLES: return "variables";
        case BINARY_SECTION_INCLUDES: return "includes";
        case BINARY_SECTION_ABI: return "abi";
        case BINARY_SECTION_END: return "end";
        default: return "unknown";
    }
}

/* Profile conversion functions */
int binary_profile_from_text(const char *text_profile, 
                            const char *profile_name,
                            binary_profile_t **binary_profile) {
    if (!text_profile || !profile_name || !binary_profile) return -1;
    
    *binary_profile = binary_profile_create(profile_name);
    if (!*binary_profile) return -1;
    
    return binary_profile_serialize(*binary_profile, text_profile, strlen(text_profile), NULL);
}

int binary_profile_to_text(const binary_profile_t *binary_profile,
                          char **text_profile) {
    if (!binary_profile || !text_profile) return -1;
    
    *text_profile = security_malloc(binary_profile->data_size + 1);
    if (!*text_profile) return -1;
    
    memcpy(*text_profile, binary_profile->data, binary_profile->data_size);
    (*text_profile)[binary_profile->data_size] = '\0';
    
    return 0;
}

/* Cache integration */
int binary_profile_cache_init(const binary_cache_config_t *config) {
    binary_init();
    
    if (config) {
        binary_state.cache_config = *config;
    } else {
        /* Default configuration */
        binary_state.cache_config.cache_dir = security_strdup("/tmp/apparmor_cache");
        binary_state.cache_config.max_cache_size = 100 * 1024 * 1024; /* 100MB */
        binary_state.cache_config.cache_ttl = 3600; /* 1 hour */
        binary_state.cache_config.enable_compression = true;
        binary_state.cache_config.enable_encryption = false;
    }
    
    return 0;
}

void binary_profile_cache_cleanup(void) {
    if (binary_state.cache_config.cache_dir) {
        security_free(binary_state.cache_config.cache_dir);
    }
}

int binary_profile_cache_put(const char *profile_name, const binary_profile_t *profile) {
    if (!profile_name || !profile) return -1;
    
    char filename[PATH_MAX];
    snprintf(filename, sizeof(filename), "%s/%s.bin", 
             binary_state.cache_config.cache_dir, profile_name);
    
    return binary_profile_save(profile, filename);
}

int binary_profile_cache_get(const char *profile_name, binary_profile_t **profile) {
    if (!profile_name || !profile) return -1;
    
    char filename[PATH_MAX];
    snprintf(filename, sizeof(filename), "%s/%s.bin", 
             binary_state.cache_config.cache_dir, profile_name);
    
    return binary_profile_load(filename, profile);
}

int binary_profile_cache_remove(const char *profile_name) {
    if (!profile_name) return -1;
    
    char filename[PATH_MAX];
    snprintf(filename, sizeof(filename), "%s/%s.bin", 
             binary_state.cache_config.cache_dir, profile_name);
    
    return unlink(filename);
}

int binary_profile_cache_clear(void) {
    char command[PATH_MAX + 20];
    snprintf(command, sizeof(command), "rm -f %s/*.bin", binary_state.cache_config.cache_dir);
    return system(command);
}

bool binary_profile_cache_exists(const char *profile_name) {
    if (!profile_name) return false;
    
    char filename[PATH_MAX];
    snprintf(filename, sizeof(filename), "%s/%s.bin", 
             binary_state.cache_config.cache_dir, profile_name);
    
    struct stat st;
    return stat(filename, &st) == 0;
}

/* Performance monitoring */
binary_profile_stats_t *binary_profile_get_stats(void) {
    binary_init();
    return &binary_state.stats;
}

void binary_profile_print_stats(const binary_profile_stats_t *stats) {
    if (!stats) return;
    
    printf("Binary Profile Statistics:\n");
    printf("  Serialization Time: %lu μs\n", stats->serialization_time_us);
    printf("  Deserialization Time: %lu μs\n", stats->deserialization_time_us);
    printf("  Compression Time: %lu μs\n", stats->compression_time_us);
    printf("  Decompression Time: %lu μs\n", stats->decompression_time_us);
    printf("  Original Size: %zu bytes\n", stats->original_size);
    printf("  Compressed Size: %zu bytes\n", stats->compressed_size);
    printf("  Compression Ratio: %.2f%%\n", stats->compression_ratio * 100);
    printf("  Cache Hits: %lu\n", stats->cache_hits);
    printf("  Cache Misses: %lu\n", stats->cache_misses);
}

void binary_profile_reset_stats(void) {
    binary_init();
    memset(&binary_state.stats, 0, sizeof(binary_state.stats));
}

/* Error handling */
const char *binary_profile_error_to_string(binary_profile_error_t error) {
    switch (error) {
        case BINARY_PROFILE_SUCCESS: return "Success";
        case BINARY_PROFILE_ERROR_INVALID_MAGIC: return "Invalid magic number";
        case BINARY_PROFILE_ERROR_INVALID_VERSION: return "Invalid version";
        case BINARY_PROFILE_ERROR_CHECKSUM_MISMATCH: return "Checksum mismatch";
        case BINARY_PROFILE_ERROR_CORRUPTED_DATA: return "Corrupted data";
        case BINARY_PROFILE_ERROR_INSUFFICIENT_MEMORY: return "Insufficient memory";
        case BINARY_PROFILE_ERROR_IO_ERROR: return "I/O error";
        case BINARY_PROFILE_ERROR_INVALID_FORMAT: return "Invalid format";
        case BINARY_PROFILE_ERROR_ENCRYPTION_FAILED: return "Encryption failed";
        case BINARY_PROFILE_ERROR_DECRYPTION_FAILED: return "Decryption failed";
        case BINARY_PROFILE_ERROR_COMPRESSION_FAILED: return "Compression failed";
        case BINARY_PROFILE_ERROR_DECOMPRESSION_FAILED: return "Decompression failed";
        default: return "Unknown error";
    }
}

/* Default options */
serialization_options_t *binary_profile_default_options(void) {
    static serialization_options_t options = {
        .compress = true,
        .encrypt = false,
        .include_debug = false,
        .optimize = true,
        .compression_level = 6,
        .encryption_key = NULL
    };
    return &options;
}

binary_cache_config_t *binary_profile_default_cache_config(void) {
    static binary_cache_config_t config = {
        .cache_dir = "/tmp/apparmor_cache",
        .max_cache_size = 100 * 1024 * 1024, /* 100MB */
        .cache_ttl = 3600, /* 1 hour */
        .enable_compression = true,
        .enable_encryption = false
    };
    return &config;
}
