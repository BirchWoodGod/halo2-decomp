#ifndef HALO2_NETWORK_STREAM_EVENTS_H
#define HALO2_NETWORK_STREAM_EVENTS_H
#include "halo2/network_state.h"
/* Queue divisions require the same nonzero, nontrapping divisors as the XBE. */
uint32_t h2_network_stream_record(h2_memory *,uint32_t stream,uint32_t sequence); /* 000966d0 ECX/EAX */
void h2_network_sequence_queue_advance(h2_memory *,uint32_t queue,uint32_t sequence); /* 001a4840 ESI/EBX */
uint8_t h2_network_stream_complete_next(h2_memory *,const h2_network_state_operations *,uint32_t stream,uint32_t kind,uint32_t sequence,uint32_t size,uint32_t elapsed); /* 00096b00 EDI, stack4 ret16 AL */
uint32_t h2_network_stream_poll_event(h2_memory *,const h2_network_state_operations *,uint32_t stream,uint32_t sequence,uint32_t size,uint32_t elapsed,uint32_t scratch4); /* 000965e0 EAX, stack3 ret12 EAX */
uint8_t h2_network_stream_retire_next(h2_memory *,const h2_network_state_operations *,uint32_t stream,uint8_t force,uint32_t kind,uint32_t sequence); /* 00096ce0 stack4 ret16 AL */
#endif
