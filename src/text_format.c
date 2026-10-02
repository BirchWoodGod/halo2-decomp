#include "halo2/text_format.h"
#include "internal/memory.h"
uint32_t h2_text_format(h2_memory *m,const h2_text_format_platform *ops,uint32_t buffer,uint32_t capacity,uint32_t format,uint32_t arguments) {
    ops->format(ops->context,buffer,capacity-1,format,arguments);
    *h2_ptr(m,buffer+capacity-1,1)=0;
    return buffer;
}
uint32_t h2_text_append_format(h2_memory *m,const h2_text_format_platform *ops,uint32_t buffer,uint32_t capacity,uint32_t format,uint32_t arguments) {
    uint32_t end=buffer;
    while (*h2_ptr(m,end,1)) ++end;
    uint32_t remaining=capacity-(end-buffer);
    ops->format(ops->context,end,remaining-1,format,arguments);
    *h2_ptr(m,end+remaining-1,1)=0;
    return buffer;
}
