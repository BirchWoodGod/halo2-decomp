#include "halo2/network_connection_setup.h"
#include "internal/memory.h"
static uint32_t ticks(h2_memory *m, const h2_network_state_operations *clock) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
}
void h2_network_connection_reset_timers(h2_memory *m, const h2_network_state_operations *clock, uint32_t connection) {
    for (uint32_t i=0;i<6;++i) {
        uint32_t slot=connection+0xa0+i*16;
        uint32_t now=ticks(m,clock);
        h2_write32(m,slot-8,now);
        h2_write32(m,slot,h2_read32(m,0x4e6398));
        h2_write32(m,slot+4,h2_read32(m,0x4e639c));
    }
}
void h2_network_stream_reset(h2_memory *m, const h2_network_state_operations *clock, uint32_t stream) {
    /* The override flag is loaded before clearing stream byte 5. */
    uint8_t overridden=*h2_ptr(m,0x510548,1);
    *h2_ptr(m,stream+5,1)=0;
    uint32_t now=overridden ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    uint32_t product=h2_read32(m,0x4cf6e8)*now;
    uint32_t sequence=(uint32_t)(((uint64_t)product*UINT32_C(0x10624dd3))>>38)&255;
    h2_write32(m,stream+0x30,sequence);
    h2_write32(m,stream+0x34,sequence);
    h2_write32(m,stream+0x3c,0);
    h2_write32(m,stream+0x40,0);
    *h2_ptr(m,stream+0x28,1)=1;
    h2_write32(m,stream+0x14,0);
    h2_write32(m,stream+0x18,0);
    h2_write32(m,stream+0x20,0);
    h2_write32(m,stream+0x24,0);
    *h2_ptr(m,stream+0x0c,1)=0;
    h2_write32(m,stream+0x44,sequence);
    h2_write32(m,stream+0x48,0);
    h2_write32(m,stream+0x950,0);
    h2_write32(m,stream+0x954,0);
    h2_write32(m,stream+0x95c,0);
    h2_write32(m,stream+0x960,0);
    h2_write32(m,stream+0x964,0);
    *h2_ptr(m,stream+0x958,1)=0;
    h2_write32(m,stream+0x94c,sequence-1);
    *h2_ptr(m,stream+0x959,1)=1;
    h2_write32(m,stream+0x968,h2_read32(m,0x4cf70c));
    h2_write32(m,stream+0x96c,h2_read32(m,0x4cf710));
    h2_write32(m,stream+0x970,h2_read32(m,0x4cf714));
    uint32_t last=h2_read32(m,0x4cf718);
    h2_write32(m,stream+0x978,0);
    h2_write32(m,stream+0x974,last);
}
