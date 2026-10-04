#ifndef HALO2_NETWORK_REPLICATION_CHANGES_H
#define HALO2_NETWORK_REPLICATION_CHANGES_H
#include "halo2/memory.h"
typedef struct {
    void *context;
    /* Virtual +0x50. All pointers are guest addresses; mask points to a
     * writable per-invocation word. Only the callback's low return byte counts. */
    uint8_t (*filter)(void *,uint32_t function,uint32_t object,uint32_t record,
        uint32_t mask,uint32_t argument1,uint32_t argument2);
} h2_replication_change_callbacks;
/* 00089710: EAX manager, EDI handle, stack mask; ret4. */
void h2_network_replication_mark_changes(h2_memory *,uint32_t manager,uint32_t handle,uint32_t mask);
/* 0008a090: stack table, ret4. Scratch is one disjoint guest word replacing
 * the original mutable stack argument. Scans exactly 1024 records. */
void h2_network_replication_flush_changes(h2_memory *,const h2_replication_change_callbacks *,uint32_t table,uint32_t scratch4);
#endif
