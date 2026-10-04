#include "halo2/format_string.h"
#include "internal/memory.h"
uint32_t h2_format_string_256(h2_memory *m,const h2_format_operations *ops,
    uint32_t destination,uint32_t format,uint32_t arguments) {
    ops->vsnprintf(ops->context,destination,255,format,arguments);
    *h2_ptr(m,destination+255,1)=0;
    return destination;
}
