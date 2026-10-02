#include "halo2/network_send.h"
#include "internal/memory.h"
#include <string.h>

uint16_t h2_network_socket_send_to_bytes(h2_memory *m, const h2_socket_send_platform *ops,
    const uint8_t address[20], uint32_t socket, uint32_t data, uint16_t length,
    uint8_t workspace[28]) {
    if (!*h2_ptr(m, 0x4d8b18, 1) || !*h2_ptr(m, 0x4d8b19, 1)) return 0xfffd;
    uint8_t local[64] = {0};
    memcpy(local, workspace, 28);
    memcpy(local+32, address, 20);
    h2_memory frame = {local, 0, sizeof(local)};
    uint8_t converted = h2_network_address_to_sockaddr(&frame, 32, 0, 56);
    memcpy(workspace, local, 28);
    if (!converted) return 0xfffd;
    uint32_t signed_length = length & 0x8000 ? (uint32_t)length | 0xffff0000u : length;
    uint32_t result = ops->send_to(ops->context, h2_read32(m, socket), data,
        signed_length, 0, workspace, h2_read32(&frame, 56));
    if ((result & 0xffff) != 0xffff) return (uint16_t)result;
    uint32_t error = ops->last_error(ops->context);
    return error == 0x2733 ? 0xfffe : error == 0x2751 ? 0xffff : 0xfffd;
}

uint16_t h2_network_socket_send_to(h2_memory *m, const h2_socket_send_platform *ops,
    uint32_t address, uint32_t socket, uint32_t data, uint16_t length, uint8_t workspace[28]) {
    if (!*h2_ptr(m,0x4d8b18,1) || !*h2_ptr(m,0x4d8b19,1)) return 0xfffd;
    return h2_network_socket_send_to_bytes(m,ops,h2_ptr(m,address,20),socket,data,length,workspace);
}
