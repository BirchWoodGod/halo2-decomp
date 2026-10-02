#ifndef HALO2_NETWORK_REGISTRATION_H
#define HALO2_NETWORK_REGISTRATION_H
#include "halo2/memory.h"
/* External SDK calls; guest arguments and original order are preserved.
 * Descriptive names, not recovered source symbols. */
typedef struct {
    void *context;
    uint32_t (*release_address)(void *,uint32_t address); /* 003cd344 */
    uint32_t (*release_key)(void *,uint32_t key); /* 003cd0e1 */
} h2_network_registration_platform;
void h2_network_registration_release(h2_memory *,const h2_network_registration_platform *); /* 000b3b10 */
#endif
