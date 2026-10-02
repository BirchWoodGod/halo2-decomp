#ifndef HALO2_NETWORK_SLOT_ALLOC_H
#define HALO2_NETWORK_SLOT_ALLOC_H
#include "halo2/network_connection_setup.h"
#include "halo2/network_storage.h"
/* Both original functions take one stack argument, ret4, DWORD result.
 * Return UINT32_MAX when disabled/full; owner is copied after reset callbacks. */
uint32_t h2_network_stream_allocate(h2_memory *,const h2_network_state_operations *,uint32_t owner); /* 000820f0 */
uint32_t h2_network_storage_allocate(h2_memory *,const h2_network_storage_operations *,uint32_t owner,uint32_t scratch8); /* 00082150 */
#endif
