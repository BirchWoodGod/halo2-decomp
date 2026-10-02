#ifndef HALO2_ONLINE_TASKS_H
#define HALO2_ONLINE_TASKS_H
#include "halo2/memory.h"
void h2_online_address_classify(h2_memory *); /* 0006bfa0 */
/* Like the original, initialization requires a successful allocation. */
void h2_online_tasks_initialize(h2_memory *, const h2_allocator *); /* 0006b3e0 */
uint32_t h2_online_task_find(h2_memory *, uint32_t kind, uint32_t owner); /* 0006b890 */
uint32_t h2_online_task_get(h2_memory *, uint32_t handle); /* 0006b910 */
typedef struct {
    void *context;
    uint32_t (*login_status)(void *, uint32_t sdk_handle);
    uint32_t (*continue_task)(void *, uint32_t sdk_handle);
    uint32_t (*prepare_cancel)(void *, uint32_t sdk_handle);
    uint32_t (*close_task)(void *, uint32_t sdk_handle);
    uint32_t (*cancel_kind33)(void *, uint32_t sdk_handle);
} h2_online_task_platform;
uint32_t h2_online_login_status(h2_memory *, const h2_online_task_platform *, uint32_t handle); /* 0006cd50 */
uint32_t h2_online_task_continue(h2_memory *, const h2_online_task_platform *, uint32_t task); /* 0006c670 */
void h2_online_task_cancel_kind33(h2_memory *, const h2_online_task_platform *, uint32_t handle); /* 0008c550 */
void h2_online_task_cancel(h2_memory *, const h2_online_task_platform *, uint32_t handle); /* 0006b640 */
void h2_online_tasks_drain(h2_memory *, const h2_online_task_platform *); /* 0006b950 */
void h2_online_tasks_dispose(h2_memory *, const h2_allocator *, const h2_online_task_platform *); /* 0006b450 */
#endif
