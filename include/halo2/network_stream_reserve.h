#ifndef HALO2_NETWORK_STREAM_RESERVE_H
#define HALO2_NETWORK_STREAM_RESERVE_H
#include "halo2/network_stream_events.h"
typedef struct {
    void *context;
    uint8_t (*blocked)(void *,uint32_t function,uint32_t stream,uint32_t reason);
} h2_stream_reserve_callbacks;
/* 00096510: ESI stream, stack timestamp, ret4; EAX sequence or UINT32_MAX.
 * Scratch8 replaces the forced-retirement outputs. Valid queue required. */
uint32_t h2_network_stream_reserve(h2_memory *,const h2_network_state_operations *,
    const h2_stream_reserve_callbacks *,uint32_t stream,uint32_t timestamp,uint32_t scratch8);
/* 00096810: ECX stream, EAX sequence, EDI bytes; requires an existing record. */
void h2_network_stream_record_size(h2_memory *,uint32_t stream,uint32_t sequence,uint32_t bytes);
#endif
