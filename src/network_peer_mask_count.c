#include "halo2/network_peer_mask_count.h"
uint32_t h2_network_peer_mask_count(uint32_t mask) {
    mask=((mask>>1)&UINT32_C(0x55555555))+(mask&UINT32_C(0x55555555));
    mask=((mask>>2)&UINT32_C(0x33333333))+(mask&UINT32_C(0x33333333));
    mask=((mask>>4)&UINT32_C(0x0f0f0f0f))+(mask&UINT32_C(0x0f0f0f0f));
    mask=((mask>>8)&UINT32_C(0x00ff00ff))+(mask&UINT32_C(0x00ff00ff));
    return (mask>>16)+(mask&UINT32_C(0xffff));
}
