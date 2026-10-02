#ifndef HALO2_RESOURCE_RELEASE_H
#define HALO2_RESOURCE_RELEASE_H
#include "halo2/memory.h"
/* Descriptive names for recovered list/pool ownership; original types unknown. */
typedef struct {
    void *context;
    void (*protect)(void *,uint32_t address,uint32_t length,uint32_t protection);
    void (*release_entry)(void *,uint32_t function,uint32_t handle);
} h2_resource_release_platform;
void h2_memory_set_protection(const h2_resource_release_platform *,uint32_t address,uint32_t length,uint32_t protection); /* 002d15da */
void h2_resource_entry_delete(h2_memory *,const h2_resource_release_platform *,uint32_t manager,uint32_t handle); /* 0013d830 */
void h2_resource_buffer_release(h2_memory *,const h2_resource_release_platform *,uint32_t payload); /* 0012d520 */
#endif
