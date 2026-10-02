#include "halo2/transport.h"
#include "halo2/data_array.h"
#include "internal/memory.h"
#include <string.h>
void h2_transport_register(h2_memory *m,uint32_t start,uint32_t stop,uint32_t update,uint32_t context) {
    /* Match each original load: the routine has no capacity check. Valid callers
     * must leave room in the eight-entry callback arrays. */
    h2_write32(m,0x4d8b20+h2_read32(m,0x4d8b1c)*4,start);
    h2_write32(m,0x4d8b40+h2_read32(m,0x4d8b1c)*4,stop);
    h2_write32(m,0x4d8b60+h2_read32(m,0x4d8b1c)*4,update);
    h2_write32(m,0x4d8b80+h2_read32(m,0x4d8b1c)*4,context);
    h2_write32(m,0x4d8b1c,h2_read32(m,0x4d8b1c)+1);
}
void h2_transport_address_initialize(h2_memory *m) {
    memset(h2_ptr(m,0x4cf790,0x144),0,0x144);
    h2_transport_register(m,0,0x7a9a0,0x7a9a0,0);
    *h2_ptr(m,0x4cf790,1)=1;
}
void h2_transport_qos_initialize(h2_memory *m,const h2_allocator *ops) {
    uint32_t allocator=h2_read32(m,0x468758);
    h2_write32(m,0x4cf8d4,0);h2_write32(m,0x4cf8d8,0);
    uint32_t array=h2_data_create(m,ops,allocator,0x450c48,32,8,0);
    h2_write32(m,0x4cf8d8,array);
}
void h2_transport_initialize(h2_memory *m,const h2_allocator *allocator,const h2_transport_operations *ops) {
    memset(h2_ptr(m,0x4d8b18,0x88),0,0x88);
    h2_transport_address_initialize(m);
    h2_transport_qos_initialize(m,allocator);
    *h2_ptr(m,0x4d8b18,1)=1;
    uint32_t link=ops->query_link(ops->context);
    if (h2_read32(m,0x55e704)!=link) h2_write32(m,0x55e704,link);
    if (link&1) ops->start_online(ops->context);
}
uint32_t h2_transport_is_active(h2_memory *m) {
    return *h2_ptr(m,0x4d8b18,1)!=0 && *h2_ptr(m,0x4d8b19,1)!=0;
}
