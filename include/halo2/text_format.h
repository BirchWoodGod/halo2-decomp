#ifndef HALO2_TEXT_FORMAT_H
#define HALO2_TEXT_FORMAT_H
#include "halo2/memory.h"
/* CRT321980 boundary. Arguments and varargs are guest addresses, not host va_list.
 * The runtime bridge implements the original bounded formatter semantics. */
typedef struct {
    void *context;
    uint32_t (*format)(void *,uint32_t destination,uint32_t limit,uint32_t format,uint32_t arguments);
} h2_text_format_platform;
uint32_t h2_text_format(h2_memory *,const h2_text_format_platform *,uint32_t buffer,uint32_t capacity,uint32_t format,uint32_t arguments); /* 0011c9c0 ESI buffer EDI capacity */
uint32_t h2_text_append_format(h2_memory *,const h2_text_format_platform *,uint32_t buffer,uint32_t capacity,uint32_t format,uint32_t arguments); /* 0011c9e0 EBX buffer EAX capacity */
#endif
