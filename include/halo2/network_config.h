#ifndef HALO2_NETWORK_CONFIG_H
#define HALO2_NETWORK_CONFIG_H
#include "halo2/memory.h"
#include "halo2/file_io.h"
/* Descriptive labels for the persisted-state path; original names unknown. */
void h2_network_config_defaults(h2_memory *); /* 0007f930 */
uint8_t h2_network_config_fields_valid(h2_memory *, uint32_t fields); /* 00153750 */
uint8_t h2_network_config_validate(h2_memory *); /* 00080660 */
/* Native caller supplies 0x114 bytes of temporary guest-addressable storage.
 * It represents the original stack-local file reference and scratch word;
 * it must not overlap engine state, source paths, or other live objects. */
uint8_t h2_network_config_load(h2_memory *, const h2_file_platform *,
    uint32_t workspace); /* 0007fa40 */
#endif
