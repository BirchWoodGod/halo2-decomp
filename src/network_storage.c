#include "halo2/network_storage.h"
#include "internal/memory.h"
static int64_t storage_signed(uint32_t x) {
    return x&0x80000000u ? (int64_t)x-INT64_C(0x100000000) : x;
}
static uint32_t storage_entry(h2_memory *m,uint32_t ring,uint32_t sequence,uint32_t stride) {
    uint32_t first=h2_read32(m,ring+0x1c),index=UINT32_MAX;
    if (storage_signed(sequence)>storage_signed(first) && storage_signed(sequence)<=storage_signed(h2_read32(m,ring+0x18))) {
        uint32_t origin=h2_read32(m,ring+0x28) ? h2_read32(m,ring+0x24) : UINT32_MAX;
        int64_t numerator=storage_signed(sequence-first-1+origin),divisor=storage_signed(h2_read32(m,ring+0x14));
        if (!divisor || (numerator==INT64_C(-2147483648) && divisor==-1)) abort();
        index=(uint32_t)(numerator%divisor);
    }
    return index==UINT32_MAX ? 0 : ring+0x2c+index*stride;
}
void h2_network_storage_clear(h2_memory *m,const h2_network_storage_operations *ops,uint32_t storage,uint32_t scratch) {
    if (*h2_ptr(m,storage+4,1)) {
        uint32_t last=h2_read32(m,storage+0x18),first=h2_read32(m,storage+0x1c);
        if (last!=first) {
            for (uint32_t sequence=first+1;storage_signed(sequence)<=storage_signed(h2_read32(m,storage+0x18));++sequence) {
                uint32_t entry=storage_entry(m,storage,sequence,12);
                uint32_t bytes=*h2_ptr(m,entry+1,1),count=h2_read32(m,storage+0x2848),owner=h2_read32(m,0x4d87f8);
                h2_write32(m,storage+0x2848,count-bytes);
                uint32_t object=h2_read32(m,owner),handle=h2_read32(m,entry+4);
                uint32_t function=h2_read32(m,h2_read32(m,object)+4);
                if (!ops->lookup(ops->context,function,object,handle,scratch)) h2_write32(m,scratch,UINT32_MAX);
                owner=h2_read32(m,0x4d87f8);object=h2_read32(m,owner);
                function=h2_read32(m,h2_read32(m,object));
                h2_write32(m,scratch+4,owner);
                ops->release(ops->context,function,object,handle,UINT32_MAX);
                if (handle) {owner=h2_read32(m,scratch+4);h2_write32(m,owner+4,h2_read32(m,owner+4)-1);}
                h2_write32(m,entry+4,0);
            }
        }
        last=h2_read32(m,storage+0x1834);first=h2_read32(m,storage+0x1838);
        if (last!=first) {
            uint32_t sequence=first+1;h2_write32(m,scratch,sequence);
            while (storage_signed(sequence)<=storage_signed(h2_read32(m,storage+0x1834))) {
                uint32_t entry=storage_entry(m,storage+0x181c,sequence,8);
                if (h2_read32(m,entry+4)) {
                    uint32_t bytes=*h2_ptr(m,entry+1,1),count=h2_read32(m,storage+0x284c),owner=h2_read32(m,0x4d87f8);
                    h2_write32(m,storage+0x284c,count-bytes);
                    uint32_t object=h2_read32(m,owner),handle=h2_read32(m,entry+4);
                    uint32_t function=h2_read32(m,h2_read32(m,object)+4);
                    if (!ops->lookup(ops->context,function,object,handle,scratch+4)) h2_write32(m,scratch+4,UINT32_MAX);
                    owner=h2_read32(m,0x4d87f8);object=h2_read32(m,owner);function=h2_read32(m,h2_read32(m,object));
                    ops->release(ops->context,function,object,handle,UINT32_MAX);
                    if (handle) h2_write32(m,owner+4,h2_read32(m,owner+4)-1);
                    sequence=h2_read32(m,scratch);
                    h2_write32(m,entry+4,0);
                }
                ++sequence;h2_write32(m,scratch,sequence);
            }
        }
    }
    *h2_ptr(m,storage+5,1)=0;
    for (uint32_t i=0;i<2;++i) {
        uint32_t ring=storage+i*0x181c;
        h2_write32(m,ring+0x18,0);h2_write32(m,ring+0x1c,0);
        h2_write32(m,ring+0x24,0);h2_write32(m,ring+0x28,0);
        *h2_ptr(m,ring+0x10,1)=1;
    }
    h2_write32(m,storage+0x2848,0);h2_write32(m,storage+0x284c,0);
}
