#ifndef HALO2_FILE_IO_H
#define HALO2_FILE_IO_H
#include "halo2/memory.h"
/* SDK semantics: read/write/close/metadata/set-end use nonzero success;
 * open/attributes/seek use UINT32_MAX as failure. Buffer addresses refer to guest memory.
 * The host owns transferred-count storage; it starts with the original buffer
 * address, as in the recovered stack local. Callbacks may leave it unchanged. */
typedef struct {
    void *context;
    uint32_t (*read)(void *, uint32_t handle, uint32_t buffer, uint32_t count, uint32_t *transferred);
    uint32_t (*write)(void *, uint32_t handle, uint32_t buffer, uint32_t count, uint32_t *transferred);
    uint32_t (*close)(void *, uint32_t handle);
    uint32_t (*last_error)(void *);
    void (*set_error)(void *, uint32_t error);
    uint32_t (*seek)(void *, uint32_t handle, uint32_t position, uint32_t high_word_pointer, uint32_t origin);
    uint32_t (*set_end)(void *, uint32_t handle);
    uint32_t (*attributes)(void *, const uint8_t path[256]);
    /* A successful query must initialize the 36-byte SDK information record. */
    uint32_t (*metadata)(void *, const uint8_t path[256], uint32_t level, uint8_t information[36]);
    uint32_t (*open)(void *, const uint8_t path[256], uint32_t access, uint32_t sharing,
        uint32_t security, uint32_t disposition, uint32_t attributes, uint32_t template_handle);
} h2_file_platform;
uint8_t h2_file_read(h2_memory *, const h2_file_platform *, uint32_t file,
    uint32_t buffer, uint32_t count, uint8_t suppress_error); /* 00136ca0 */
uint8_t h2_file_write(h2_memory *, const h2_file_platform *, uint32_t file,
    uint32_t buffer, uint32_t count); /* 00136d00 */
uint8_t h2_file_close(h2_memory *, const h2_file_platform *, uint32_t file); /* 00136bb0 */
uint8_t h2_file_seek(h2_memory *, const h2_file_platform *, uint32_t file,
    uint32_t position, uint8_t suppress_error); /* 00136bf0 */
uint8_t h2_file_set_end(h2_memory *, const h2_file_platform *, uint32_t file,
    uint32_t position); /* 00136c40 */
uint8_t h2_file_exists(h2_memory *, const h2_file_platform *, uint32_t file); /* 001368f0 */
uint8_t h2_file_size(h2_memory *, const h2_file_platform *, uint32_t file,
    uint32_t output); /* 00136e90 */
uint8_t h2_file_open(h2_memory *, const h2_file_platform *, uint32_t file,
    uint32_t flags, uint32_t error_output); /* 00136970 */
#endif
