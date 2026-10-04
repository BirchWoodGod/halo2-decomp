#ifndef HALO2_NETWORK_CONNECTION_PACKET_H
#define HALO2_NETWORK_CONNECTION_PACKET_H
#include "halo2/network_packet.h"
/* 000931a0: ECX optional primary stream, EAX connection index; stack endpoint,
 * secondary size/data and optional accounted-size output; ret16, void.
 * Scratch is 0x1828 disjoint guest bytes (packet and submission workspace). */
void h2_network_connection_send_packet(h2_memory *,const h2_network_state_operations *,
    const h2_socket_send_platform *,uint32_t stream,uint32_t index,uint32_t endpoint,
    uint32_t secondary_size,uint32_t secondary,uint32_t size_output,uint32_t scratch,
    uint8_t address_workspace[28]);
#endif
