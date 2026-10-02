#include "halo2/network_endpoint.h"
#include "internal/memory.h"
#include <string.h>
static uint32_t ticks(h2_memory *m, const h2_network_state_operations *ops) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : ops->ticks(ops->context);
}
static int64_t signed_value(uint32_t x) {
    return x & 0x80000000u ? (int64_t)x-INT64_C(0x100000000) : x;
}
void h2_network_statistics_advance(h2_memory *m, const h2_network_state_operations *ops, uint32_t p) {
    uint32_t now = ticks(m,ops);
    if (!h2_read32(m,p+0x10)) h2_write32(m,p+0x10,now);
    uint32_t period = h2_read32(m,p+0x20), last = h2_read32(m,p+0x10);
    if (now < last+period) return;
    if (!period) abort(); /* Original DIV faults for a zero period. */
    if (signed_value((now-last)/period) > 20) {
        h2_write32(m,p+0xcc,0); h2_write32(m,p+0xd0,0);
        memset(h2_ptr(m,p+0x2c,160),0,160);
        h2_write32(m,p+0x10,now);
        return;
    }
    do {
        uint32_t index = h2_read32(m,p+0x28);
        uint32_t first = h2_read32(m,p+0x14);
        uint32_t second_total = h2_read32(m,p+0xd0);
        h2_write32(m,p+0xcc,h2_read32(m,p+0xcc)-h2_read32(m,p+index*8+0x2c));
        second_total -= h2_read32(m,p+index*8+0x30);
        h2_write32(m,p+0xcc,h2_read32(m,p+0xcc)+first);
        uint32_t second = h2_read32(m,p+0x18);
        h2_write32(m,p+0xd0,second_total);
        h2_write32(m,p+0xd0,second_total+second);
        h2_write32(m,p+index*8+0x2c,first);
        h2_write32(m,p+index*8+0x30,h2_read32(m,p+0x18));
        uint32_t next = (uint32_t)(signed_value(h2_read32(m,p+0x28)+1)%20);
        last = h2_read32(m,p+0x10);
        h2_write32(m,p+0x14,0); h2_write32(m,p+0x18,0); h2_write32(m,p+0x28,next);
        period = h2_read32(m,p+0x20);
        last += period;
        h2_write32(m,p+0x10,last);
    } while (now >= last+period);
}
void h2_network_samples_reset(h2_memory *m, const h2_network_state_operations *ops, uint32_t p) {
    uint32_t now = ticks(m,ops);
    for (uint32_t i=0; signed_value(i)<signed_value(h2_read32(m,p)); ++i) {
        h2_write32(m,p+8+i*8,now); h2_write32(m,p+12+i*8,0);
    }
    h2_write32(m,p+4,0); h2_write32(m,p+0x108,0); h2_write32(m,p+0x10c,0);
}
void h2_network_samples_add(h2_memory *m, const h2_network_state_operations *ops, uint32_t p, uint32_t value) {
    uint32_t now = ticks(m,ops), index = h2_read32(m,p+4);
    uint32_t elapsed = now-h2_read32(m,p+index*8+8);
    uint32_t total = h2_read32(m,p+0x108);
    h2_write32(m,p+0x10c,elapsed);
    total -= h2_read32(m,p+index*8+12);
    h2_write32(m,p+0x108,total);
    h2_write32(m,p+index*8+8,now);
    h2_write32(m,p+h2_read32(m,p+4)*8+12,value);
    total = h2_read32(m,p+0x108);
    uint32_t next = h2_read32(m,p+4)+1;
    h2_write32(m,p+0x108,total+value);
    int64_t divisor = signed_value(h2_read32(m,p));
    if (!divisor || (next==0x80000000u && divisor==-1)) abort();
    h2_write32(m,p+4,(uint32_t)(signed_value(next)%divisor));
}
void h2_network_statistics_initialize(h2_memory *m,uint32_t statistics,int32_t interval) {
    uint32_t bits=h2_read32(m,0x45dccc);
    float numerator;memcpy(&numerator,&bits,4);
    float denominator=(float)interval;
    float scale=numerator/denominator;
    memcpy(&bits,&scale,4);
    memset(h2_ptr(m,statistics,0xd4),0,0xd4);
    h2_write32(m,statistics+0x1c,(uint32_t)interval);
    h2_write32(m,statistics+0x20,(uint32_t)(interval/20));
    h2_write32(m,statistics+0x24,bits);
}
uint8_t h2_network_endpoint_open(h2_memory *m,const h2_endpoint_operations *ops,uint32_t endpoint) {
    if (ops->open(ops->context,3,1000,0,endpoint+0xc) &&
        ops->open(ops->context,2,1001,1,endpoint+0x18) &&
        ops->open(ops->context,3,1005,0,endpoint+0x10) &&
        ops->open(ops->context,3,1006,0,endpoint+0x14)) {
        *h2_ptr(m,endpoint+8,1)=1;
    } else ops->close_all(ops->context,endpoint);
    return *h2_ptr(m,endpoint+8,1);
}
uint8_t h2_network_endpoint_initialize(h2_memory *m,const h2_endpoint_operations *ops,uint32_t endpoint) {
    for (unsigned i=0;i<4;i++) h2_network_statistics_initialize(m,endpoint+0x228+i*0xd8,2000);
    (void)h2_network_endpoint_open(m,ops,endpoint);
    *h2_ptr(m,endpoint,1)=1;
    return 1;
}
