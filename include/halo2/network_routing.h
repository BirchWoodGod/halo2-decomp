#ifndef HALO2_NETWORK_ROUTING_H
#define HALO2_NETWORK_ROUTING_H
#include "halo2/network_send.h"
uint32_t h2_network_endpoint_find_route(h2_memory *, uint32_t endpoint, uint32_t kind, uint32_t address); /* 00092e50 */
uint32_t h2_network_endpoint_find_connection(h2_memory *, uint32_t endpoint, uint32_t kind, uint32_t address); /* 00092ef0 */
void h2_network_endpoint_send(h2_memory *, const h2_socket_send_platform *, uint32_t endpoint,
    uint32_t kind, uint32_t address, uint32_t size, uint32_t data, uint8_t workspace[28]); /* 00093730 */
uint8_t h2_network_endpoint_remove_route(h2_memory *,uint32_t endpoint,uint32_t connection); /* 00092e00 */
#endif
