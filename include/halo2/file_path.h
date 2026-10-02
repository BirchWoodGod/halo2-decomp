#ifndef HALO2_FILE_PATH_H
#define HALO2_FILE_PATH_H
#include "halo2/memory.h"
/* Original Xbox path syntax; host filesystem translation is still separate.
 * Append/resolve require nonoverlapping source and destination storage.
 * Append expects an existing path of at most 255 bytes and may touch byte 256. */
void h2_file_path_append(h2_memory *, uint32_t destination, uint32_t component); /* 00137320 */
void h2_file_path_parent(h2_memory *, uint32_t path); /* 001373c0 */
void h2_file_path_resolve(h2_memory *, uint32_t destination, uint32_t path); /* 001374c0 */
/* Host-stack adapter for engine routines with a local path buffer; not another
 * recovered original function. Output must not alias guest memory. */
void h2_file_path_resolve_buffer(h2_memory *, uint8_t destination[256], uint32_t path);
#endif
