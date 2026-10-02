#ifndef HALO2_ASYNC_TASK_CREATE_H
#define HALO2_ASYNC_TASK_CREATE_H
#include "halo2/async_tasks.h"
typedef struct {
    void *context;
    /* SDK 003cd156; arguments are guest values, including array pointers. */
    uint32_t (*create)(void *, uint32_t, uint32_t, uint32_t, uint32_t,
                       uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                       uint32_t, uint32_t, uint32_t);
    const h2_async_task_platform *tasks;
    uint32_t scratch; /* Disjoint 0x304-byte guest temporary, per invocation. */
} h2_async_task_create_platform;
/* 0007b4c0: ECX kind, EDX count, EAX option, stack records60; ret4. */
uint32_t h2_async_task_create(h2_memory *, const h2_async_task_create_platform *,
    uint32_t kind, uint32_t count, uint32_t option, uint32_t records60);
#endif
