#ifndef HALO2_NETWORK_ACCEPT_HELPERS_H
#define HALO2_NETWORK_ACCEPT_HELPERS_H
#include "halo2/memory.h"
uint8_t h2_network_connection_flags_valid(uint32_t flags); /* 000880b0 ECX, AL */
uint8_t h2_network_connection_copy_address(h2_memory *,uint32_t connection,uint32_t address20); /* 00075930 EAX,ECX,AL */
uint8_t h2_network_address_equal(h2_memory *,uint32_t first,uint32_t second,uint8_t compare_port); /* 0007af80 EBX,stack second/port,ret8,AL */
#endif
