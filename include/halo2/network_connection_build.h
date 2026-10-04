#ifndef HALO2_NETWORK_CONNECTION_BUILD_H
#define HALO2_NETWORK_CONNECTION_BUILD_H
#include "halo2/network_connection_packet.h"
#include "halo2/network_stream_reserve.h"
#include "halo2/format_string.h"
typedef struct {
    void *context;
    uint32_t (*invoke)(void *,uint32_t function,uint32_t object,uint32_t count,
        uint32_t a,uint32_t b,uint32_t c,uint32_t d);
    h2_format_operations formatting;
} h2_connection_build_callbacks;
/* 00088980: AL reserve; stack connection, bitstream, fill byte, secondary size,
 * secondary pointer, optional accounted/primary/secondary outputs; ret32, void.
 * Scratch0x1f84 is disjoint guest storage. Its first0x74c bytes replace original
 * locals (including preserved boolean padding); remaining storage is for callees.
 * Valid component indices0..6, mapped bitstream buffers, nontrapping alignment
 * and padding fitting the original1536-byte local buffer are prerequisites. */
void h2_network_connection_build_packet(h2_memory *,const h2_network_state_operations *,
    const h2_socket_send_platform *,const h2_stream_reserve_callbacks *,
    const h2_connection_build_callbacks *,uint8_t reserve,uint32_t connection,
    uint32_t bitstream,uint8_t fill,uint32_t secondary_size,uint32_t secondary,
    uint32_t accounted_output,uint32_t primary_output,uint32_t secondary_output,
    uint32_t scratch,uint8_t address_workspace[28]);
#endif
