#ifndef HALO2_TEXT_CODEC_H
#define HALO2_TEXT_CODEC_H
#include "halo2/memory.h"
/* Original permissive byte/16-bit text conversion, not Unicode normalization. */
uint32_t h2_text_encode_character(h2_memory *, uint32_t output, uint32_t value, uint32_t capacity); /* 001405a0 */
void h2_text_encode_string(h2_memory *, uint32_t source, uint32_t output, uint32_t capacity); /* 00140650 */
void h2_text_decode_string(h2_memory *, uint32_t source, uint32_t output, uint32_t capacity); /* 00140440 */
#endif
