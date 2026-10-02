#include "halo2/discovery.h"
#include "internal/memory.h"
#include <string.h>
static int64_t discovery_signed(uint32_t x) {
    return x&0x80000000u ? (int64_t)x-INT64_C(0x100000000) : x;
}
static int32_t discovery_short(h2_memory *m,uint32_t p) {
    const uint8_t *b=h2_ptr(m,p,2);uint32_t value=b[0]|(uint32_t)b[1]<<8;
    return value&0x8000 ? (int32_t)value-65536 : (int32_t)value;
}
void h2_discovery_store_reply(h2_memory *m,const h2_network_state_operations *clock,uint32_t reply) {
    if (!*h2_ptr(m,0x4d8eb4,1) || discovery_signed(h2_read32(m,0x4d8ec4))<=0) return;
    uint32_t free_slot=0xffffffff,replacement=0xffffffff,match=0xffffffff;
    uint32_t entry=h2_read32(m,0x4d8ec8);
    for (uint32_t i=0;discovery_signed(i)<discovery_signed(h2_read32(m,0x4d8ec4));++i,entry+=0x784) {
        if (!*h2_ptr(m,entry,1)) {
            if (free_slot==0xffffffff) free_slot=i;
        } else {
            if (!memcmp(h2_ptr(m,entry+0xe0,36),h2_ptr(m,reply+0x7c,36),36)) {match=i;break;}
            int32_t rank=discovery_short(m,reply+0xaa);
            if (rank && discovery_short(m,reply+0x20)==0 && rank<discovery_short(m,entry+0x10e)) replacement=i;
        }
    }
    uint32_t selected=match!=0xffffffff ? match : free_slot!=0xffffffff ? free_slot : replacement;
    if (selected==0xffffffff) return;
    entry=h2_read32(m,0x4d8ec8)+selected*0x784;
    if (selected!=match) memset(h2_ptr(m,entry,0x784),0,0x784);
    if (memcmp(h2_ptr(m,entry+0x70,0x714),h2_ptr(m,reply+12,0x714),0x714)) {
        /* Original REP MOVSD copies forwards, including overlapping inputs. */
        for (uint32_t i=0;i<0x714;i+=4) h2_write32(m,entry+0x70+i,h2_read32(m,reply+12+i));
        *h2_ptr(m,entry+0x6c,1)=1;*h2_ptr(m,0x4d8eb5,1)=1;
    }
    *h2_ptr(m,entry,1)=1;
    if (*h2_ptr(m,0x510548,1)) {
        uint32_t now=h2_read32(m,0x51054c);
        *h2_ptr(m,entry+0x44,1)=1;h2_write32(m,entry+4,now);
    } else {
        uint32_t now=clock->ticks(clock->context);
        h2_write32(m,entry+4,now);*h2_ptr(m,entry+0x44,1)=1;
    }
}
void h2_message_handle_broadcast_reply(h2_memory *m,const h2_network_state_operations *clock,uint32_t reply,uint32_t address) {
    (void)address;
    if (discovery_short(m,reply)!=2 || !*h2_ptr(m,0x4d8eb4,1)) return;
    uint32_t low=h2_read32(m,0x4d8ebc),high=h2_read32(m,0x4d8ec0);
    if (h2_read32(m,reply+4)==low && h2_read32(m,reply+8)==high) h2_discovery_store_reply(m,clock,reply);
}

void h2_discovery_update(h2_memory *m,const h2_network_state_operations *clock,
    const h2_socket_send_platform *send,const h2_message_codec_platform *codec,
    uint32_t local,uint32_t packet_scratch,uint8_t address_workspace[28]) {
    if (!*h2_ptr(m,0x4d8eb4,1)) return;
    uint8_t override=*h2_ptr(m,0x510548,1);
    uint32_t previous=h2_read32(m,0x4d8eb8);
    uint32_t now=override ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    if (discovery_signed(now-previous)>1500) {
        uint32_t low=h2_read32(m,0x4d8ebc),high=h2_read32(m,0x4d8ec0);
        memset(h2_ptr(m,local,12),0,12);
        h2_write32(m,local+4,low);h2_write32(m,local+8,high);
        uint32_t writer=h2_read32(m,0x4d8eb0);
        *h2_ptr(m,local,1)=2;
        uint8_t *address=h2_ptr(m,local+12,20);
        address[18]=4;address[19]=0;
        h2_write32(m,local+12,0xffffffff);
        address[16]=0xe9;address[17]=3;
        h2_message_writer_enqueue(m,clock,send,codec,writer,local+12,2,12,local,packet_scratch,address_workspace);
        now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
        h2_write32(m,0x4d8eb8,now);
    }
    for (uint32_t i=0;discovery_signed(i)<discovery_signed(h2_read32(m,0x4d8ec4));++i) {
        uint32_t entry=h2_read32(m,0x4d8ec8)+i*0x784;
        if (!*h2_ptr(m,entry,1)) continue;
        override=*h2_ptr(m,0x510548,1);
        previous=h2_read32(m,entry+4);
        now=override ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
        if (discovery_signed(now-previous)>2000) {
            memset(h2_ptr(m,entry,0x784),0,0x784);
            *h2_ptr(m,0x4d8eb5,1)=1;
        }
    }
}

uint8_t h2_discovery_start(h2_memory *m,const h2_random_sources *sources,
    const h2_random_bytes_platform *platform,uint32_t cache,uint32_t count) {
    uint8_t active=*h2_ptr(m,0x4d8eb4,1);
    if (active || !*h2_ptr(m,0x4d8b18,1) || !*h2_ptr(m,0x4d8b19,1)) return active;
    *h2_ptr(m,0x4d8eb4,1)=1;
    *h2_ptr(m,0x4d8eb5,1)=0;
    h2_write32(m,0x4d8eb8,0);
    h2_random_identity(m,sources,platform,0x4d8ebc);
    uint32_t bytes=count*UINT32_C(0x784);
    h2_write32(m,0x4d8ec4,count);h2_write32(m,0x4d8ec8,cache);
    if (bytes) memset(h2_ptr(m,cache,bytes),0,bytes);
    return *h2_ptr(m,0x4d8eb4,1);
}

void h2_discovery_cancel_tasks(h2_memory *m,const h2_online_task_platform *online,
    const h2_async_task_platform *async) {
    uint32_t handle=h2_read32(m,0x4d8ef0);
    if (handle!=UINT32_MAX) {
        h2_online_task_cancel(m,online,handle);
        h2_write32(m,0x4d8ef0,UINT32_MAX);
    }
    handle=h2_read32(m,0x4d8ef4);
    if (handle!=UINT32_MAX) {
        h2_async_task_release(m,async,handle);
        h2_write32(m,0x4d8ef4,UINT32_MAX);
    }
    *h2_ptr(m,0x4d8ecc,1)=0;
    h2_write32(m,0x4d8ef8,0);h2_write32(m,0x4d8efc,0);
}
void h2_discovery_stop(h2_memory *m,const h2_online_task_platform *online,
    const h2_async_task_platform *async,const h2_allocator *allocator) {
    if (*h2_ptr(m,0x4d8f08,1)) h2_discovery_cancel_tasks(m,online,async);
    else if (*h2_ptr(m,0x4d8eb4,1)) *h2_ptr(m,0x4d8eb4,1)=0;
    uint32_t allocation=h2_read32(m,0x4d8f18);
    if (allocation) {
        uint32_t identity=h2_read32(m,0x4d8f10);
        allocator->release(allocator->context,identity,allocation);
        h2_write32(m,0x4d8f18,0);h2_write32(m,0x4d8f14,0);
    }
}
