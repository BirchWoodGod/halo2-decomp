#ifndef HALO2_NETWORK_PEER_MASK_COUNT_H
#define HALO2_NETWORK_PEER_MASK_COUNT_H
#include <stdint.h>
/* 00063ca0: ECX mask, EAX population count, no stack arguments. */
uint32_t h2_network_peer_mask_count(uint32_t mask);
#endif
