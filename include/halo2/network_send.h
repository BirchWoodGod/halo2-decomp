#ifndef HALO2_NETWORK_SEND_H
#define HALO2_NETWORK_SEND_H
#include "halo2/network_address.h"
typedef struct {
    void *context;
    uint32_t (*send_to)(void *, uint32_t handle, uint32_t data, uint32_t length,
        uint32_t flags, const uint8_t *address, uint32_t address_length);
    uint32_t (*last_error)(void *);
} h2_socket_send_platform;
/* AX result and signed 16-bit length retain their original bit patterns.
 * Workspace models 28 incoming stack bytes and must not alias guest memory. */
uint16_t h2_network_socket_send_to(h2_memory *, const h2_socket_send_platform *,
    uint32_t address, uint32_t socket, uint32_t data, uint16_t length,
    uint8_t workspace[28]); /* 000b5110 */
/* Adapter for the caller's stack-local engine address. */
uint16_t h2_network_socket_send_to_bytes(h2_memory *, const h2_socket_send_platform *,
    const uint8_t address[20], uint32_t socket, uint32_t data, uint16_t length, uint8_t workspace[28]);
#endif
