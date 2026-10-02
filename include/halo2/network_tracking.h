#ifndef HALO2_NETWORK_TRACKING_H
#define HALO2_NETWORK_TRACKING_H
#include "halo2/memory.h"
#include "halo2/resource_release.h"
#include "halo2/online_tasks.h"
/* Descriptive names: original class/type names have not been established. */
uint32_t h2_network_tracking_find_free(h2_memory *); /* 0008e1e0 */
uint32_t h2_network_tracking_queue_write(h2_memory *,uint32_t object,uint32_t data,uint32_t length); /* 0008e500 */
uint32_t h2_network_tracking_queue_read(h2_memory *,uint32_t object,uint32_t data,uint32_t length); /* 0008e580 */
uint8_t h2_network_task_start_read(h2_memory *,uint32_t object,uint32_t token,uint32_t a,uint32_t b,uint32_t c,uint16_t flags); /* 00080f70 */
uint8_t h2_network_task_start_write(h2_memory *,uint32_t object,uint32_t token,uint32_t a,uint32_t b,uint32_t c,uint16_t flags); /* 00080ff0 */
typedef struct {
    void *context;
    uint8_t (*invoke)(void *,uint32_t function,uint32_t object);
} h2_network_task_callbacks;
void h2_network_task_complete(h2_memory *,const h2_network_task_callbacks *,uint32_t object,uint32_t reason); /* 00081050 */
void h2_network_tracking_remove(h2_memory *,const h2_network_task_callbacks *,const h2_online_task_platform *,const h2_resource_release_platform *,uint32_t index,uint32_t reason); /* 0008e0f0 */
#endif
