#include "halo2/network_stream_reserve.h"
#include "internal/memory.h"
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
uint32_t h2_network_stream_reserve(h2_memory *m,const h2_network_state_operations *clock,const h2_stream_reserve_callbacks *c,uint32_t stream,uint32_t timestamp,uint32_t scratch) {
    uint32_t function=h2_read32(m,h2_read32(m,stream)+4);
    if(c->blocked(c->context,function,stream,0)) return UINT32_MAX;
    if(sv(h2_read32(m,stream+0x30)-h2_read32(m,stream+0x34))>=sv(h2_read32(m,stream+0x2c)))
        (void)h2_network_stream_retire_next(m,clock,stream,1,scratch+4,scratch);
    uint32_t latest=h2_read32(m,stream+0x30);
    if(sv(h2_read32(m,stream+0x94c)-latest+0x80)<=0 ||
       sv(latest-h2_read32(m,stream+0x34))>=sv(h2_read32(m,stream+0x2c)) ||
       sv(latest-h2_read32(m,stream+0x44)+1)>=0x80) {
        *h2_ptr(m,stream+5,1)=1;return UINT32_MAX;
    }
    uint32_t sequence=latest+1;
    if(sv(sequence)>sv(latest)) {
        h2_write32(m,stream+0x40,h2_read32(m,stream+0x40)+(sequence-latest));
        h2_write32(m,stream+0x30,sequence);
    }
    uint32_t difference=sequence-h2_read32(m,stream+0x44);
    *h2_ptr(m,stream+0x959,1)=0;
    uint32_t record=h2_network_stream_record(m,stream,sequence);
    for(uint32_t i=0;i<16;i+=4) h2_write32(m,record+i,0);
    uint8_t *distance=h2_ptr(m,record+12,2);distance[0]=(uint8_t)difference;distance[1]=(uint8_t)(difference>>8);
    h2_write32(m,record,timestamp);h2_write32(m,record+8,UINT32_MAX);
    return sequence;
}
void h2_network_stream_record_size(h2_memory *m,uint32_t stream,uint32_t sequence,uint32_t bytes) {
    uint32_t record=h2_network_stream_record(m,stream,sequence);
    h2_write32(m,record+4,bytes);
    h2_write32(m,stream+0x48,h2_read32(m,stream+0x48)+bytes);
}
