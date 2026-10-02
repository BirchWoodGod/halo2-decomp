#ifndef HALO2_NETWORK_PACKET_H
#define HALO2_NETWORK_PACKET_H
#include "halo2/memory.h"
#include "halo2/network_endpoint.h"
#include "halo2/network_routing.h"
/* Scratch models the original 0x1004-byte stack frame and must be disjoint
 * from packet/endpoint state. Address workspace follows the send API. */
void h2_network_packet_submit(h2_memory *, const h2_network_state_operations *,
    const h2_socket_send_platform *, uint32_t packet, uint32_t endpoint,
    uint32_t scratch, uint8_t address_workspace[28]); /* 000932f0 */
/* Scratch is 0x1828 bytes: packet object followed by submission scratch. */
void h2_network_packet_send_datagram(h2_memory *, const h2_network_state_operations *,
    const h2_socket_send_platform *, uint32_t stream, uint32_t address, uint32_t endpoint,
    uint32_t size_output, uint32_t scratch, uint8_t address_workspace[28]); /* 00093100 */
void h2_network_packet_pack(h2_memory *, uint32_t packet, uint32_t destination, uint32_t size_output); /* 00093590 */
uint8_t h2_network_packet_unpack(h2_memory *, uint32_t packet, uint32_t size, uint32_t source); /* 00093610 */
uint32_t h2_network_packet_accounted_size(h2_memory *, uint32_t packet); /* 000936c0 */
#endif
