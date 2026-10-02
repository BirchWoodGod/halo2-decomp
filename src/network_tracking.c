#include "halo2/network_tracking.h"
#include "halo2/crc.h"
#include "internal/memory.h"
static uint16_t read16(h2_memory *m,uint32_t p) {
    const uint8_t *b=h2_ptr(m,p,2);return (uint16_t)(b[0]|(uint16_t)b[1]<<8);
}
static void write16(h2_memory *m,uint32_t p,uint16_t v) {
    uint8_t *b=h2_ptr(m,p,2);b[0]=(uint8_t)v;b[1]=(uint8_t)(v>>8);
}
uint32_t h2_network_tracking_find_free(h2_memory *m) {
    for (uint32_t i=0;i<32;++i) if (!h2_read32(m,0x4d8c28+i*20)) return i;
    return UINT32_MAX;
}
static uint32_t list_free(h2_memory *m,uint32_t list) {
    for (uint32_t i=0;i<16;++i) if (h2_read32(m,list+i*4)==UINT32_MAX) return i;
    return UINT32_MAX;
}
uint32_t h2_network_tracking_queue_write(h2_memory *m,uint32_t object,uint32_t data,uint32_t length) {
    uint32_t index=h2_network_tracking_find_free(m),slot=list_free(m,0x4d8ba8);
    uint16_t type=read16(m,object+8);
    if (type==1||type==2) {h2_write32(m,data,UINT32_MAX);h2_crc_update(m,data,data,length);}
    uint32_t entry=0x4d8c28+index*20;
    h2_write32(m,entry+8,length);h2_write32(m,entry+12,data);
    h2_write32(m,entry,object);h2_write32(m,entry+4,UINT32_MAX);
    h2_write32(m,0x4d8ba8+slot*4,index);
    return index;
}
uint32_t h2_network_tracking_queue_read(h2_memory *m,uint32_t object,uint32_t data,uint32_t length) {
    uint32_t index=h2_network_tracking_find_free(m),slot=list_free(m,0x4d8be8);
    uint32_t entry=0x4d8c28+index*20;
    h2_write32(m,entry+4,UINT32_MAX);h2_write32(m,entry+8,length);
    h2_write32(m,entry,object);h2_write32(m,entry+12,data);
    h2_write32(m,0x4d8be8+slot*4,index);
    return index;
}
static void task_arguments(h2_memory *m,uint32_t object,uint32_t token,uint32_t a,uint32_t b,uint32_t c,uint16_t flags) {
    h2_write32(m,object+0x10,token);h2_write32(m,object+0x14,a);
    h2_write32(m,object+0x18,b);h2_write32(m,object+0x1c,c);write16(m,object+6,flags);
}
uint8_t h2_network_task_start_read(h2_memory *m,uint32_t object,uint32_t token,uint32_t a,uint32_t b,uint32_t c,uint16_t flags) {
    if (read16(m,object+10)) return 0;
    uint16_t type=read16(m,object+8);
    task_arguments(m,object,token,a,b,c,flags);
    uint16_t status=read16(m,object+4);
    if (type && (status&2) && !(status&8)) return 1;
    uint32_t index=h2_network_tracking_queue_read(m,object,h2_read32(m,object+0x24),h2_read32(m,object+0x28));
    h2_write32(m,object+0x20,index);
    if (index==UINT32_MAX) return 0;
    type=read16(m,object+8);write16(m,object+10,1);
    if (type!=4) *h2_ptr(m,object+4,1)&=0xfd;
    return 1;
}
uint8_t h2_network_task_start_write(h2_memory *m,uint32_t object,uint32_t token,uint32_t a,uint32_t b,uint32_t c,uint16_t flags) {
    if (read16(m,object+10)) return 0;
    task_arguments(m,object,token,a,b,c,flags);
    uint32_t index=h2_network_tracking_queue_write(m,object,h2_read32(m,object+0x24),h2_read32(m,object+0x28));
    h2_write32(m,object+0x20,index);
    if (index==UINT32_MAX) return 0;
    write16(m,object+10,2);return 1;
}

static void restart_task(h2_memory *m,uint32_t object,uint16_t kind,int count) {
    uint16_t flags=read16(m,object+6);
    if (count && kind==1) h2_write32(m,0x55e700,h2_read32(m,0x55e700)+1);
    uint32_t a=h2_read32(m,object+0x14),b=h2_read32(m,object+0x18),c=h2_read32(m,object+0x1c);
    if (count && kind==2) h2_write32(m,0x55e700,h2_read32(m,0x55e700)+1);
    uint32_t token=h2_read32(m,object+0x10);
    if (kind==1) (void)h2_network_task_start_read(m,object,token,a,b,c,flags);
    else (void)h2_network_task_start_write(m,object,token,a,b,c,flags);
}
void h2_network_task_complete(h2_memory *m,const h2_network_task_callbacks *callbacks,uint32_t object,uint32_t reason) {
    write16(m,object+12,read16(m,object+10));
    uint16_t saved=read16(m,object+4);
    write16(m,object+14,(uint16_t)reason);write16(m,object+10,0);
    h2_write32(m,object+0x20,UINT32_MAX);
    uint16_t kind=read16(m,object+12);
    if (reason==1) {
        if (kind==2) write16(m,object+4,saved&0xffeb);
        else if (kind==1) write16(m,object+4,(saved&0xffe3)|2);
    } else if (kind==1 && reason==6) write16(m,object+4,saved|4);
    else if (reason==7 && !(read16(m,object+6)&1) && (kind==1||kind==2)) restart_task(m,object,kind,0);
    int failed=0;
    uint32_t table=h2_read32(m,object);
    if (table) {
        kind=read16(m,object+12);saved|=*h2_ptr(m,object+4,1)&4;
        uint32_t function=kind==2 ? h2_read32(m,table+0x14) : kind==1 ? h2_read32(m,table+0x18) : 0;
        if (function && !callbacks->invoke(callbacks->context,function,object)) {
            write16(m,object+4,saved);failed=1;
        }
    }
    if (reason==1 && !failed) return;
    if (*h2_ptr(m,object+6,1)&2) return;
    table=h2_read32(m,object);
    if (table) {
        uint32_t function=h2_read32(m,table+0x10);
        if (function) {
            uint8_t result=callbacks->invoke(callbacks->context,function,object);
            if (result) {*h2_ptr(m,object+4,1)|=2;*h2_ptr(m,object+4,1)|=8;return;}
            *h2_ptr(m,object+4,1)&=0xfd;*h2_ptr(m,object+4,1)&=0xf7;
        }
    }
    kind=read16(m,object+12);
    if (kind==1||kind==2) restart_task(m,object,kind,1);
    else h2_write32(m,0x55e700,h2_read32(m,0x55e700)+1);
}

void h2_network_tracking_remove(h2_memory *m,const h2_network_task_callbacks *callbacks,const h2_online_task_platform *online,const h2_resource_release_platform *resources,uint32_t index,uint32_t reason) {
    uint32_t record=0x4d8c28+index*20;
    if (!h2_read32(m,record)) return;
    uint32_t task=h2_read32(m,record+4);
    if (task!=UINT32_MAX) h2_online_task_cancel(m,online,task);
    h2_network_task_complete(m,callbacks,h2_read32(m,record),reason);
    uint32_t object=h2_read32(m,record);
    if (read16(m,object+8)==4 && h2_read32(m,object+0x20)==UINT32_MAX) {
        uint32_t payload=h2_read32(m,object+0x24);
        if (payload) {
            h2_resource_buffer_release(m,resources,payload);
            h2_write32(m,object+0x24,0);h2_write32(m,object+0x28,0);
        }
    }
    h2_write32(m,record,0);h2_write32(m,record+4,UINT32_MAX);
    h2_write32(m,record+8,0);h2_write32(m,record+12,0);
    for (uint32_t list=0x4d8ba8;list<0x4d8c28;list+=64) {
        for (uint32_t i=0;i<16;++i) {
            uint32_t slot=list+i*4;
            if (h2_read32(m,slot)==index) h2_write32(m,slot,UINT32_MAX);
            if (i && h2_read32(m,slot-4)==UINT32_MAX) {
                h2_write32(m,slot-4,h2_read32(m,slot));h2_write32(m,slot,UINT32_MAX);
            }
        }
    }
}
