#ifndef HALO2_MESSAGE_READER_H
#define HALO2_MESSAGE_READER_H
#include "halo2/memory.h"
/* Engine callback dependencies, not implemented socket/platform services.
 * decode receives the descriptor's original callback address. deliver represents
 * 000938e0 with handler in EDX, type in EAX, payload in ECX and address on stack.
 * Payload is reused after deliver returns; copy it if retaining the message. */
typedef struct {
    void *context;
    uint8_t (*decode)(void *,uint32_t function,uint32_t stream,uint32_t size,uint32_t payload);
    void (*deliver)(void *,uint32_t handler,uint32_t type,uint32_t payload,uint32_t address);
} h2_message_reader_operations;
/* Scratch: type/size words followed by 65536 payload bytes (0x10008 total).
 * Supply incoming payload bytes to reproduce original stack contents. Keep
 * scratch disjoint from stream, owner, table, wire data and codec workspace. */
uint8_t h2_message_reader_process(h2_memory *,const h2_message_reader_operations *,
    uint32_t owner,uint32_t address,uint32_t stream,uint32_t scratch); /* 0007afd0 */
#endif
