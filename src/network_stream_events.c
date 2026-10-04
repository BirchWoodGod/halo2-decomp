#include "halo2/network_stream_events.h"
#include "halo2/network_observer_retry.h"
#include "internal/memory.h"
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
static uint32_t word(h2_memory *m,uint32_t p) {const uint8_t *b=h2_ptr(m,p,2);return b[0]|((uint32_t)b[1]<<8);}
static void put_word(h2_memory *m,uint32_t p,uint32_t v) {uint8_t *b=h2_ptr(m,p,2);b[0]=(uint8_t)v;b[1]=(uint8_t)(v>>8);}
static uint32_t ticks(h2_memory *m,const h2_network_state_operations *c) {return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : c->ticks(c->context);}
static uint32_t record_at(h2_memory *m,uint32_t stream,uint32_t sequence,uint32_t oldest) {
    uint32_t index=UINT32_MAX;
    if(sv(sequence)>sv(oldest) && sv(sequence)<=sv(h2_read32(m,stream+0x30))) {
        uint32_t head=h2_read32(m,stream+0x40) ? h2_read32(m,stream+0x3c) : UINT32_MAX;
        index=(uint32_t)(sv(sequence-oldest-1+head)%sv(h2_read32(m,stream+0x2c)));
    }
    return index==UINT32_MAX ? 0 : stream+0x14c+(index<<4);
}
uint32_t h2_network_stream_record(h2_memory *m,uint32_t stream,uint32_t sequence) {
    return record_at(m,stream,sequence,h2_read32(m,stream+0x34));
}
void h2_network_sequence_queue_advance(h2_memory *m,uint32_t queue,uint32_t sequence) {
    uint32_t amount=sequence-h2_read32(m,queue+12);
    if(sv(amount)<=0) return;
    uint32_t count=h2_read32(m,queue+24);
    if(sv(count)>=sv(amount)) {
        uint32_t head=(uint32_t)(sv(h2_read32(m,queue+20)+amount)%sv(h2_read32(m,queue+16)));
        h2_write32(m,queue+24,count-amount);h2_write32(m,queue+20,head);
    }
    h2_write32(m,queue+12,sequence);
}
uint8_t h2_network_stream_complete_next(h2_memory *m,const h2_network_state_operations *c,uint32_t stream,uint32_t kind,uint32_t sequence,uint32_t size,uint32_t elapsed) {
    uint32_t next=h2_read32(m,stream+0x44)+1;
    uint32_t record=h2_network_stream_record(m,stream,next);
    if(!record) return 0;
    uint32_t flags=word(m,record+14);
    if(flags&1) {
        h2_write32(m,kind,1+((flags&2)!=0));h2_write32(m,sequence,next);
        h2_write32(m,size,h2_read32(m,record+4));h2_write32(m,elapsed,h2_read32(m,record+8));
        *h2_ptr(m,record+14,1)|=4;
    } else {
        uint32_t previous=h2_read32(m,record),now=ticks(m,c),age=now-previous;
        uint32_t threshold=h2_read32(m,stream+0x974)+h2_read32(m,stream+0x978);
        if(sv(age)>=sv(threshold) || sv(h2_read32(m,stream+0x94c)-next)>=sv(h2_read32(m,0x4cf6f0))) {
            h2_write32(m,record+8,age);h2_write32(m,kind,3);h2_write32(m,sequence,next);
            h2_write32(m,size,h2_read32(m,record+4));
            uint32_t value=h2_read32(m,record+8);uint8_t override=*h2_ptr(m,0x510548,1);
            h2_write32(m,elapsed,value);*h2_ptr(m,record+14,1)|=8;
            if(!override) (void)c->ticks(c->context);
            value=h2_read32(m,stream+0x978)+h2_read32(m,0x4cf71c);
            h2_write32(m,stream+0x978,value);
            uint32_t cap=h2_read32(m,0x4cf720);
            h2_write32(m,stream+0x978,sv(value)>sv(cap) ? cap : value);
        }
    }
    flags=word(m,record+14);
    if(!(flags&12)) return 0;
    put_word(m,record+14,flags|16);
    uint32_t pending=h2_read32(m,stream+0x48);
    h2_write32(m,stream+0x44,next);
    h2_write32(m,stream+0x48,pending-h2_read32(m,record+4));
    return 1;
}
uint32_t h2_network_stream_poll_event(h2_memory *m,const h2_network_state_operations *c,uint32_t stream,uint32_t sequence,uint32_t size,uint32_t elapsed,uint32_t scratch) {
    h2_write32(m,scratch,0);
    if(h2_network_stream_complete_next(m,c,stream,scratch,sequence,size,elapsed)) return h2_read32(m,scratch);
    uint32_t oldest=h2_read32(m,stream+0x34);
    if(h2_read32(m,stream+0x30)==oldest) return h2_read32(m,scratch);
    uint32_t end=h2_read32(m,stream+0x30),next=h2_read32(m,stream+0x44)+1;
    for(;sv(next)<sv(end);++next) {
        uint32_t record=record_at(m,stream,next,oldest),flags=word(m,record+14);
        if((flags&1) && !(flags&2)) {
            h2_write32(m,sequence,next);h2_write32(m,size,h2_read32(m,record+4));
            h2_write32(m,elapsed,h2_read32(m,record+8));*h2_ptr(m,record+14,1)|=2;return 4;
        }
    }
    return h2_read32(m,scratch);
}
uint8_t h2_network_stream_retire_next(h2_memory *m,const h2_network_state_operations *c,uint32_t stream,uint8_t force,uint32_t kind,uint32_t sequence) {
    h2_write32(m,kind,0);
    if(h2_read32(m,stream+0x30)==h2_read32(m,stream+0x34)) return 0;
    uint32_t next=h2_read32(m,stream+0x34)+1;
    if(sv(next)>sv(h2_read32(m,stream+0x44))) return 0;
    uint32_t record=h2_network_stream_record(m,stream,next),flags=word(m,record+14);
    if(!(flags&4) && !force && !(flags&1)) {
        uint32_t age=h2_network_elapsed(m,c,h2_read32(m,record));
        if(sv(age)<sv(h2_read32(m,stream+0x974)+h2_read32(m,0x4cf6f4))) return 0;
    }
    h2_write32(m,kind,6);h2_write32(m,sequence,next);
    h2_network_sequence_queue_advance(m,stream+0x28,next);return 1;
}
