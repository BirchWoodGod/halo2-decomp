#ifndef HALO2_NETWORK_PARAMETERS_H
#define HALO2_NETWORK_PARAMETERS_H
#include "halo2/memory.h"
#include "halo2/online_tasks.h"
#include "halo2/async_tasks.h"
typedef struct {
    void *context;
    /* The original query's stack output is discarded by this caller. */
    void (*query)(void *, uint32_t identity, uint32_t buffer);
    void (*release)(void *, uint32_t identity, uint32_t buffer, uint32_t flags);
} h2_parameter_buffer_platform;
void h2_network_parameter_request_remove(h2_memory *,
    const h2_parameter_buffer_platform *, uint32_t owner, uint32_t request); /* 0006ddb0 */
void h2_network_parameter_operation_dispose(h2_memory *,
    const h2_online_task_platform *, const h2_async_task_platform *,
    const h2_parameter_buffer_platform *, uint32_t operation); /* 00090c80 */
void h2_network_parameter_runtime_dispose(h2_memory *, const h2_online_task_platform *); /* 00072d30 */
void h2_network_parameter_set_initialize(h2_memory *,uint32_t set,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f,uint32_t g); /* 0006de50 */
void h2_network_parameter5_initialize(h2_memory *,uint32_t parameter,uint32_t set); /* 0006f090 */
void h2_network_parameter6_initialize(h2_memory *,uint32_t parameter,uint32_t set); /* 00070190 */
void h2_network_parameter_runtime_initialize(h2_memory *,uint32_t dependency,uint32_t owner); /* 00072c80 */
uint8_t h2_network_parameters_initialize(h2_memory *, uint32_t session,
    uint32_t dependency_ecx, uint32_t dependency_edx,
    uint32_t dependency_a, uint32_t dependency_b, uint32_t dependency_c); /* 00058ee0 */
#endif
