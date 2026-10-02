#include "halo2/arena.h"
#include "halo2/crc.h"
#include "internal/memory.h"
#include <string.h>
static void checksum_size(h2_memory *m,uint32_t size) {
    uint8_t bytes[4]={(uint8_t)size,(uint8_t)(size>>8),(uint8_t)(size>>16),(uint8_t)(size>>24)};
    h2_crc_update_bytes(m,0x4e608c,bytes,4);
}
static uint32_t reserve_exact(h2_memory *m,uint32_t size) {
    uint32_t offset=h2_read32(m,0x4e6084),base=h2_read32(m,0x4e6080);
    h2_write32(m,0x4e6084,offset+size);
    checksum_size(m,size);
    return base+offset;
}
uint32_t h2_arena_reserve(h2_memory *m,uint32_t size) {
    return reserve_exact(m,(size+3)&UINT32_C(0xfffffffc));
}
uint32_t h2_arena_reserve_aligned(h2_memory *m,uint32_t size,uint32_t bits) {
    uint32_t alignment=UINT32_C(1)<<(bits&31);
    uint32_t start=reserve_exact(m,(alignment+size+3)&UINT32_C(0xfffffffc));
    return (start+alignment-1)&~(alignment-1);
}
uint32_t h2_arena_allocator_allocate(h2_memory *m,uint32_t size) {
    return h2_arena_reserve(m,size);
}
void h2_arena_allocator_release(uint32_t address) { (void)address; }
void h2_arena_initialize(h2_memory *m,const h2_arena_platform *platform) {
    if (*h2_ptr(m,0x4e3b60,1)) return;
    h2_write32(m,0x4e608c,UINT32_MAX);
    uint32_t base=platform->allocate(platform->context,0x3be000,0x40000);
    h2_write32(m,0x4e6080,base);
    memset(h2_ptr(m,base,0x3fe000),0,0x3fe000);
    platform->prepare_save_storage(platform->context);
    uint32_t state=reserve_exact(m,0x1288);
    uint32_t offset=h2_read32(m,0x4e6084);
    base=h2_read32(m,0x4e6080);
    h2_write32(m,0x4e6094,state);
    uint32_t allocator=base+offset;
    h2_write32(m,0x4e6084,offset+4);
    *h2_ptr(m,0x4e3b60,1)=1;
    checksum_size(m,4);
    h2_write32(m,0x510c2c,allocator);
    if (allocator) h2_write32(m,allocator,0x453498);
}
static uint32_t allocate(void *ctx,uint32_t identity,uint32_t size) {
    (void)identity;return h2_arena_allocator_allocate(ctx,size);
}
static void release(void *ctx,uint32_t identity,uint32_t address) {
    (void)ctx;(void)identity;h2_arena_allocator_release(address);
}
h2_allocator h2_arena_allocator(h2_memory *m) { return (h2_allocator){m,allocate,release}; }

void h2_arena_dispose(h2_memory *m,const h2_arena_platform *platform) {
    if (!*h2_ptr(m,0x4e3b60,1)) return;
    *h2_ptr(m,0x5020d8,1)=0;
    platform->close_save_storage(platform->context);
    memset(h2_ptr(m,0x4e3b60,0x2540),0,0x2540);
}
static void copy_string(h2_memory *m,uint32_t target,uint32_t source,uint32_t size) {
    uint8_t ch=1;
    for (uint32_t i=0;i<size;i++) {
        if (ch) ch=*h2_ptr(m,source+i,1);
        *h2_ptr(m,target+i,1)=ch;
    }
    *h2_ptr(m,target+size-1,1)=0;
}
void h2_arena_initialize_for_map(h2_memory *m,const h2_arena_platform *platform) {
    uint32_t base=h2_read32(m,0x4e6080);
    platform->protect(platform->context,base,0x3be000,4);
    platform->protect(platform->context,base+0x3be000,0x40000,0x404);
    *h2_ptr(m,0x4e3b61,1)=1;
    *h2_ptr(m,0x4e3b62,1)=0;
    *h2_ptr(m,0x4e3b63,1)=0;
    memset(h2_ptr(m,0x4e3b68,0x2510),0,0x2510);
    h2_write32(m,0x4e6090,UINT32_MAX);
    memset(h2_ptr(m,h2_read32(m,0x4e6094),0x1288),0,0x1288);
    h2_write32(m,h2_read32(m,0x4e6094),h2_read32(m,0x4e608c));
    h2_write32(m,h2_read32(m,0x4e6094)+4,h2_read32(m,0x4e6080));
    copy_string(m,h2_read32(m,0x4e6094)+8,0x5478bc,0x100);
    copy_string(m,h2_read32(m,0x4e6094)+0x108,0x450698,0x20);
    h2_write32(m,h2_read32(m,0x4e6094)+0x128,h2_read32(m,0x547844));
    uint32_t source=h2_read32(m,0x4e6948)+8,target=h2_read32(m,0x4e6094)+0x130;
    for (uint32_t i=0;i<0x1118;i+=4) h2_write32(m,target+i,h2_read32(m,source+i));
    *h2_ptr(m,0x4e6098,1)=0;
}
