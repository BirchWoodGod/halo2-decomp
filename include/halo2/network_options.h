#ifndef HALO2_NETWORK_OPTIONS_H
#define HALO2_NETWORK_OPTIONS_H
#include "halo2/memory.h"
/* Explicit getsockopt/setsockopt boundaries. Values remain Xbox option values.
 * A getter can update both value and length even when returning an error. */
typedef struct {
    void *context;
    uint32_t (*get)(void *,uint32_t handle,uint32_t level,uint32_t option,uint32_t *value,uint32_t *length);
    uint32_t (*set)(void *,uint32_t handle,uint32_t level,uint32_t option,const uint8_t *value,uint32_t length);
    void (*last_error)(void *);
} h2_socket_option_platform;
uint32_t h2_network_option_code(uint32_t option); /* 000b4da0 */
uint32_t h2_network_socket_get_option(h2_memory *,const h2_socket_option_platform *,uint32_t socket,uint32_t option); /* 000b4e00 */
uint8_t h2_network_socket_set_option(h2_memory *,const h2_socket_option_platform *,uint32_t socket,uint32_t option,uint32_t value); /* 000b4e70 */
#endif
