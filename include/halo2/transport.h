#ifndef HALO2_TRANSPORT_H
#define HALO2_TRANSPORT_H
#include "halo2/memory.h"
/* Link query is Xbox SDK 0036c47d; online startup 0008d840 remains unrecovered.
 * Callers must implement these dependencies; reporting a fake offline link is
 * not an implementation of network support. */
typedef struct {
    void *context;
    uint32_t (*query_link)(void *);
    void (*start_online)(void *);
} h2_transport_operations;
void h2_transport_initialize(h2_memory *,const h2_allocator *,const h2_transport_operations *); /* 0008d690 */
void h2_transport_address_initialize(h2_memory *); /* 0007a840 */
void h2_transport_qos_initialize(h2_memory *,const h2_allocator *); /* 0007b3e0 */
void h2_transport_register(h2_memory *,uint32_t start,uint32_t stop,uint32_t update,uint32_t context); /* 0008d770 */
uint32_t h2_transport_is_active(h2_memory *); /* 0008d7c0 */
#endif
