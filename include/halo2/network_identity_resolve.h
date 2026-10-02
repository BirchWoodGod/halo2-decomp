#ifndef HALO2_NETWORK_IDENTITY_RESOLVE_H
#define HALO2_NETWORK_IDENTITY_RESOLVE_H
#include "halo2/memory.h"
typedef struct {
    void *context;
    uint32_t (*resolve)(void *,uint32_t ipv4,uint32_t identity36,uint32_t key_metadata20); /* SDK003cd32d */
    uint32_t scratch32; /* Disjoint per-invocation guest temporary. */
} h2_identity_resolve_platform;
uint8_t h2_network_identity_resolve(h2_memory *,const h2_identity_resolve_platform *,
    uint32_t address,uint32_t direct,uint32_t index4,uint32_t key8,uint32_t metadata16,uint32_t identity36); /* 0007ab60 ECX,EDX,stack4 outputs,ret16 */
#endif
