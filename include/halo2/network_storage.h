#ifndef HALO2_NETWORK_STORAGE_H
#define HALO2_NETWORK_STORAGE_H
#include "halo2/memory.h"
#include "halo2/network_messages.h"
/* Original virtual methods remain explicit boundaries. object is the guest
 * this pointer and function is the method address read from its vtable. */
typedef struct {
    void *context;
    uint8_t (*lookup)(void *,uint32_t function,uint32_t object,uint32_t handle,uint32_t output);
    void (*release)(void *,uint32_t function,uint32_t object,uint32_t handle,uint32_t value);
} h2_network_storage_operations;
/* scratch is eight disjoint guest bytes retaining incoming stack contents. */
void h2_network_storage_clear(h2_memory *,const h2_network_storage_operations *,uint32_t storage,uint32_t scratch); /* 00094bf0 */
typedef struct {
    void *context;
    uint8_t (*poll)(void *,uint32_t function,uint32_t storage,uint32_t value);
    uint32_t (*allocate)(void *,uint32_t function,uint32_t object,uint32_t bytes,uint32_t a,uint32_t b);
    void (*collect)(void *,uint32_t function,uint32_t object,uint32_t value);
} h2_network_storage_queue_operations;
/* scratch: 0x10037 disjoint guest bytes. The first 0x34 bytes retain incoming
 * stack contents before initialization; data starts at +0x38 and is zeroed.
 * Retry termination is supplied by the original virtual poll/allocator protocol. */
void h2_network_storage_enqueue(h2_memory *,const h2_network_storage_queue_operations *,const h2_message_codec_platform *,uint32_t storage,uint32_t type,uint32_t size,uint32_t payload,uint32_t scratch); /* 00095580 */
#endif
