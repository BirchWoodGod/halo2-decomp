#ifndef HALO2_ASYNC_TASK_RESULT_H
#define HALO2_ASYNC_TASK_RESULT_H
#include "halo2/memory.h"
/* 0007b7b0: EAX handle, EDI output32, stack result index; AL success. */
uint8_t h2_async_task_result(h2_memory *, uint32_t handle, uint32_t index,
                             uint32_t output32);
#endif
