#include "halo2/network_observer.h"
#include "halo2/network_address.h"
#include "halo2/network_endpoint.h"
#include "internal/memory.h"
#include <string.h>
static int observer_address_valid(h2_memory *m,uint32_t address) {
    if (!address) return 0;
    const uint8_t *p=h2_ptr(m,address+18,2);
    uint32_t width=p[0]|(uint32_t)p[1]<<8;
    if (width==4 || width==0xffff) return h2_read32(m,address)!=0;
    if (width==16) {
        for (uint32_t i=0;i<16;i+=2) {
            p=h2_ptr(m,address+i,2);if (p[0] || p[1]) return 1;
        }
    }
    return 0;
}
void h2_network_observer_detach(h2_memory *m,const h2_network_state_operations *clock,
    const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,
    const h2_network_registration_platform *registration,uint32_t observer,uint32_t index,uint32_t mark,uint32_t reason,
    uint32_t local,uint32_t packet,uint8_t workspace[28]) {
    uint32_t entry=observer+0xa8+index*0x528,connection_id=h2_read32(m,entry+12);
    /* The original reuses its first stack argument for converted IPv4 output. */
    h2_write32(m,local+12,mark);
    if (connection_id!=UINT32_MAX) {
        uint32_t connection=h2_read32(m,0x4d87d4)+connection_id*0xf8;
        uint32_t state=h2_read32(m,connection+0x54);
        if (state>2 && !(state&0x80000000u))
            h2_network_connection_close(m,clock,send,codec,callbacks,connection,reason,local,packet,workspace);
    }
    uint32_t address=entry+0x5c;
    if (!observer_address_valid(m,address)) return;
    h2_message_writer_flush_address(m,clock,send,h2_read32(m,observer+8),address,packet,workspace);
    if (mark&255) {
        uint32_t bit=h2_read32(m,entry+0x3c);
        if (bit<4) h2_write32(m,entry+0x38,h2_read32(m,entry+0x38)|(1u<<bit));
    }
    if (h2_network_address_registered_ipv4(m,address,local+12))
        (void)registration->release_address(registration->context,h2_read32(m,local+12));
    for (uint32_t i=0;i<20;i+=4) h2_write32(m,address+i,0);
}

void h2_network_observer_release_slot(h2_memory *m,const h2_network_state_operations *clock,
    const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,
    const h2_network_registration_platform *registration,const h2_network_storage_operations *storage_ops,const h2_async_task_platform *async,
    uint32_t observer,uint32_t index,uint32_t local,uint32_t packet,uint32_t storage_scratch,uint8_t workspace[28]) {
    uint32_t entry=observer+0xa8+index*0x528;
    h2_network_observer_detach(m,clock,send,codec,callbacks,registration,observer,index,0,14,local,packet,workspace);
    uint32_t id=h2_read32(m,entry+12);
    if (id!=UINT32_MAX) {
        uint32_t connection=h2_read32(m,0x4d87d4)+id*0xf8;
        h2_network_connection_dispose(m,clock,send,codec,callbacks,storage_ops,connection,local,packet,storage_scratch,workspace);
        h2_write32(m,entry+12,UINT32_MAX);
    }
    uint32_t handle=h2_read32(m,entry+0x70);
    if (handle!=UINT32_MAX) {
        h2_async_task_release(m,async,handle);
        h2_write32(m,entry+0x70,UINT32_MAX);
    }
    memset(h2_ptr(m,entry,0x528),0,0x528);
    h2_write32(m,entry+12,UINT32_MAX);h2_write32(m,entry+0x70,UINT32_MAX);
}
void h2_network_observer_dispose(h2_memory *m,const h2_network_state_operations *clock,
    const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,
    const h2_network_registration_platform *registration,const h2_network_storage_operations *storage_ops,const h2_async_task_platform *async,
    uint32_t observer,uint32_t local,uint32_t packet,uint32_t storage_scratch,uint8_t workspace[28]) {
    for (uint32_t i=0;i<15;++i)
        if (h2_read32(m,observer+0xa8+i*0x528))
            h2_network_observer_release_slot(m,clock,send,codec,callbacks,registration,storage_ops,async,observer,i,local,packet,storage_scratch,workspace);
    memset(h2_ptr(m,observer+0x14,0x90),0,0x90);
    h2_write32(m,observer+0x10,0);h2_write32(m,observer+12,0);h2_write32(m,observer+4,0);
}

static uint32_t observer_time(h2_memory *m,const h2_network_state_operations *clock) {
    return *h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
}
void h2_network_observer_set_state(h2_memory *m,const h2_network_state_operations *clock,const h2_observer_events *events,
    uint32_t observer,uint32_t index,uint32_t state) {
    uint32_t entry=observer+0xa8+index*0x528;
    if (h2_read32(m,entry)==state) return;
    h2_write32(m,entry,state);h2_write32(m,entry+4,observer_time(m,clock));
    if (h2_read32(m,entry)!=1) return;
    for (uint32_t i=0;i<4;++i) if (*h2_ptr(m,entry+9,1)&(1u<<i)) {
        uint32_t object=h2_read32(m,observer+0x14+i*36),function=h2_read32(m,h2_read32(m,object)+16);
        events->state_one(events->context,function,object,index);
    }
}
static void observer_notify(h2_memory *m,const h2_observer_events *events,uint32_t observer,uint32_t entry,uint32_t index,uint32_t connected) {
    for (uint32_t i=0;i<4;++i) if (*h2_ptr(m,entry+9,1)&(1u<<i)) {
        uint32_t identifier=h2_read32(m,entry+0x10),object=h2_read32(m,observer+0x14+i*36);
        uint32_t function=h2_read32(m,h2_read32(m,object)+12);
        events->connection(events->context,function,object,index,identifier,connected);
    }
}
static void observer_attempt_increment(h2_memory *m,uint32_t entry) {
    uint8_t *p=h2_ptr(m,entry+10,2);uint32_t value=(p[0]|(uint32_t)p[1]<<8)+1;
    p[0]=(uint8_t)value;p[1]=(uint8_t)(value>>8);
}
void h2_network_observer_update_slot(h2_memory *m,const h2_network_state_operations *clock,
    const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,
    const h2_network_registration_platform *registration,const h2_observer_events *events,uint32_t observer,uint32_t index,
    uint32_t local,uint32_t packet,uint8_t workspace[28]) {
    uint32_t entry=observer+0xa8+index*0x528,state=h2_read32(m,entry),connection=0;
    if (!state) return;
    uint32_t id=h2_read32(m,entry+12);
    if (id==UINT32_MAX) {
        h2_network_observer_detach(m,clock,send,codec,callbacks,registration,observer,index,1,0,local,packet,workspace);
        h2_network_observer_set_state(m,clock,events,observer,index,1);
    } else {
        connection=h2_read32(m,0x4d87d4)+id*0xf8;
        /* Preserve the original table-driven dispatch; only its three valid
         * targets are native. Invalid state-table targets are not supported. */
        uint32_t branch=*h2_ptr(m,0x77303+state,1);
        uint32_t cs=(branch==1 || branch==2) ? h2_read32(m,connection+0x54) : 0;
        if (branch==1) {
            if (cs==5) h2_network_observer_set_state(m,clock,events,observer,index,7);
            else if (cs<=2 || (cs&0x80000000u)) {
                uint32_t reason=h2_read32(m,connection+0x58);
                if (reason==1 || reason==2 || reason==5) {
                    h2_network_observer_detach(m,clock,send,codec,callbacks,registration,observer,index,1,15,local,packet,workspace);
                    h2_network_observer_set_state(m,clock,events,observer,index,1);
                } else {
                    if (reason==9) {
                        h2_network_observer_detach(m,clock,send,codec,callbacks,registration,observer,index,1,0,local,packet,workspace);
                        h2_network_observer_set_state(m,clock,events,observer,index,2);
                        memset(h2_ptr(m,entry+10,2),0,2);
                    }
                    h2_network_observer_set_state(m,clock,events,observer,index,h2_read32(m,entry)==6 ? 5 : 9);
                    observer_attempt_increment(m,entry);
                }
            }
        } else if (branch==2) {
            if (cs!=5) {
                if (cs<=2 || (cs&0x80000000u)) {
                    h2_network_observer_set_state(m,clock,events,observer,index,9);
                    memset(h2_ptr(m,entry+10,2),0,2);
                } else h2_network_observer_set_state(m,clock,events,observer,index,8);
            }
        } else if (branch!=0) abort();
    }
    if (*h2_ptr(m,entry+8,1)&2) {
        if (!connection || h2_read32(m,connection+0x54)!=5 || h2_read32(m,connection+0x4c)!=h2_read32(m,entry+0x10)) {
            observer_notify(m,events,observer,entry,index,0);
            *h2_ptr(m,entry+8,1)&=(uint8_t)~2u;h2_write32(m,entry+0x10,UINT32_MAX);
        }
        if (*h2_ptr(m,entry+8,1)&2) return;
    }
    if (h2_read32(m,entry)!=7) return;
    h2_write32(m,entry+0x94,observer_time(m,clock));
    memset(h2_ptr(m,entry+0xa0,28),0,28);memset(h2_ptr(m,entry+0xc8,0xac),0,0xac);
    memset(h2_ptr(m,entry+0x178,28),0,28);memset(h2_ptr(m,entry+0x1a0,0xac),0,0xac);
    h2_network_samples_reset(m,clock,entry+0x250);h2_network_samples_reset(m,clock,entry+0x360);
    uint32_t initial=h2_read32(m,0x45dbcc);
    h2_write32(m,entry+0x480,UINT32_MAX);h2_write32(m,entry+0x488,UINT32_MAX);
    uint8_t override=*h2_ptr(m,0x510548,1);h2_write32(m,entry+0x484,initial);
    uint32_t now=override ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    h2_write32(m,entry+0x470,now-1000);
    const uint8_t *p=h2_ptr(m,0x485ac0,2);uint32_t interval=p[0]|(uint32_t)p[1]<<8;
    if (!interval || (interval&0x8000)) interval=60;
    uint32_t low=h2_read32(m,0x4e6398),high=h2_read32(m,0x4e639c);
    h2_write32(m,entry+0x47c,high-(low<interval));
    uint8_t flags=*h2_ptr(m,entry+8,1);h2_write32(m,entry+0x478,low-interval);
    *h2_ptr(m,entry+8,1)=flags|6;h2_write32(m,entry+0x10,h2_read32(m,connection+0x4c));
    observer_notify(m,events,observer,entry,index,1);
}

void h2_network_observer_close_connections(h2_memory *m,const h2_network_state_operations *clock,
    const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,
    const h2_network_registration_platform *registration,const h2_observer_events *events,const h2_network_storage_operations *storage_ops,
    uint32_t observer,uint32_t local,uint32_t packet,uint32_t storage_scratch,uint8_t workspace[28]) {
    for (uint32_t i=0;i<15;++i) {
        uint32_t entry=observer+0xa8+i*0x528;
        if (!h2_read32(m,entry)) continue;
        uint32_t connection=h2_read32(m,0x4d87d4)+h2_read32(m,entry+12)*0xf8;
        uint32_t state=h2_read32(m,connection+0x54);
        if (state>2 && !(state&0x80000000u)) {
            h2_network_connection_close(m,clock,send,codec,callbacks,connection,3,local,packet,workspace);
            h2_network_observer_update_slot(m,clock,send,codec,callbacks,registration,events,observer,i,local,packet,workspace);
        }
        connection=h2_read32(m,0x4d87d4)+h2_read32(m,entry+12)*0xf8;
        h2_network_connection_dispose(m,clock,send,codec,callbacks,storage_ops,connection,local,packet,storage_scratch,workspace);
        h2_write32(m,entry+12,UINT32_MAX);
    }
}
