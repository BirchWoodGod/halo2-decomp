#ifndef HALO2_ASYNC_TASKS_H
#define HALO2_ASYNC_TASKS_H
#include "halo2/memory.h"
typedef struct {
    void *context;
    uint32_t (*release)(void *, uint32_t task); /* SDK 003cd172 */
} h2_async_task_platform;
void h2_async_task_release(h2_memory *, const h2_async_task_platform *, uint32_t handle); /* 0007b650 */
uint8_t h2_async_task_is_idle(h2_memory *, uint32_t handle); /* 0007b6c0 */
#endif
