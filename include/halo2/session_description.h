#ifndef HALO2_SESSION_DESCRIPTION_H
#define HALO2_SESSION_DESCRIPTION_H
#include "halo2/memory.h"
uint8_t h2_session_description_valid(h2_memory *, uint32_t description); /* 0007b880 */
/* 76 bytes of caller-owned guest scratch replace original stack temporaries.
 * Supply their incoming bytes; they can affect truncated reads. Scratch must
 * be disjoint from stream, input and description and include readable padding
 * if unterminated text is supplied, like the original stack. */
uint8_t h2_session_description_read(h2_memory *, uint32_t stream, uint32_t description, uint32_t scratch); /* 0007c110 */
/* Writer scratch is 64 bytes: ID (12), config (16), captured count (4),
 * name (32). Incoming name-tail bytes are emitted just like original stack
 * padding. Scratch must be disjoint from all live input/output objects. */
void h2_session_description_write(h2_memory *, uint32_t stream, uint32_t description, uint32_t scratch); /* 0007ba10 */
void h2_message_broadcast_reply_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload, uint32_t scratch); /* 000ac730 */
uint8_t h2_message_broadcast_reply_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload, uint32_t scratch); /* 000ac7a0 */
#endif
