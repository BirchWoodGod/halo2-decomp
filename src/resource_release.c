#include "halo2/resource_release.h"
#include "halo2/data_array.h"
#include "internal/memory.h"
void h2_memory_set_protection(const h2_resource_release_platform *p,uint32_t address,uint32_t length,uint32_t protection) {
    if (length) p->protect(p->context,address,length,protection);
}
static uint32_t entry(h2_memory *m,uint32_t manager,uint32_t handle) {
    return h2_read32(m,h2_read32(m,manager+0x64)+0x44)+(handle&0xffff)*24;
}
void h2_resource_entry_delete(h2_memory *m,const h2_resource_release_platform *p,uint32_t manager,uint32_t handle) {
    uint32_t selected=entry(m,manager,handle),function=h2_read32(m,manager+0x20);
    if (function) p->release_entry(p->context,function,handle);
    uint32_t previous=h2_read32(m,selected+0x10);
    if (previous==UINT32_MAX) h2_write32(m,manager+0x3c,h2_read32(m,selected+12));
    else h2_write32(m,entry(m,manager,previous)+12,h2_read32(m,selected+12));
    uint32_t next=h2_read32(m,selected+12);
    if (next==UINT32_MAX) h2_write32(m,manager+0x40,h2_read32(m,selected+0x10));
    else h2_write32(m,entry(m,manager,next)+0x10,h2_read32(m,selected+0x10));
    h2_data_delete(m,h2_read32(m,manager+0x64),handle);
}
void h2_resource_buffer_release(h2_memory *m,const h2_resource_release_platform *p,uint32_t payload) {
    uint32_t handle=h2_read32(m,payload-0x24);
    uint32_t selected=h2_read32(m,h2_read32(m,0x4e6454)+0x44)+(handle&0xffff)*40;
    uint32_t address=h2_read32(m,payload-0x1c),length=h2_read32(m,payload-0x18);
    h2_memory_set_protection(p,address,length,0x404);
    *h2_ptr(m,selected+2,1)&=0xfe;
    uint32_t next=h2_read32(m,payload-4),previous=h2_read32(m,payload-8);
    h2_write32(m,payload-0x20,0);
    if (next) h2_write32(m,next+0x1c,previous);
    uint32_t manager;
    if (previous) {
        manager=h2_read32(m,0x4e6464);h2_write32(m,previous+0x20,next);
        handle=h2_read32(m,payload-0x24);
    } else {
        handle=h2_read32(m,payload-0x24);manager=h2_read32(m,0x4e6464);
        h2_write32(m,0x4e645c,next);
    }
    h2_resource_entry_delete(m,p,manager,handle);
}
