#include "halo2/network_connection_allocate.h"
#include "internal/memory.h"
uint8_t h2_network_connection_initialize(h2_memory *m,const h2_network_state_operations *clock,const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,const h2_network_storage_operations *storage_ops,uint32_t connection,uint32_t index,uint32_t flags,uint32_t endpoint,uint32_t writer,uint32_t provider,uint32_t config,uint32_t local,uint32_t packet,uint32_t storage_local,uint8_t workspace[28]) {
    h2_write32(m,connection+0x54,1);h2_write32(m,connection+0x58,0);
    for (uint32_t i=0;i<20;i+=4) h2_write32(m,connection+0x5c+i,0);
    h2_write32(m,connection+0x48,flags);h2_write32(m,connection+0x44,index);
    h2_write32(m,connection,endpoint);h2_write32(m,connection+8,provider);h2_write32(m,connection+4,writer);
    h2_write32(m,connection+0x4c,UINT32_MAX);h2_write32(m,connection+0x50,UINT32_MAX);h2_write32(m,connection+12,config);
    h2_write32(m,connection+0x20,0);
    for (uint32_t i=0;i<24;i+=4) h2_write32(m,connection+0x24+i,0);
    h2_write32(m,connection+0x3c,0);h2_write32(m,connection+0x40,0);
    if (*h2_ptr(m,connection+0x48,1)&8) {
        uint32_t slot=h2_network_stream_allocate(m,clock,0);h2_write32(m,connection+0x10,slot);
        if (slot==UINT32_MAX) goto fail;
        uint32_t address=h2_read32(m,0x4d87d8)+slot*0x97c;
        uint32_t entry=connection+0x24+h2_read32(m,connection+0x20)*8;
        h2_write32(m,entry+4,address);h2_write32(m,entry,0x31);
        h2_write32(m,connection+0x20,h2_read32(m,connection+0x20)+1);
    }
    if (*h2_ptr(m,connection+0x48,1)&16) {
        uint32_t slot=h2_network_storage_allocate(m,storage_ops,0,storage_local);h2_write32(m,connection+0x14,slot);
        if (slot==UINT32_MAX) goto fail;
        uint32_t count=h2_read32(m,connection+0x20),address=h2_read32(m,0x4d87dc)+slot*0x2850;
        uint32_t entry=connection+0x24+count*8;
        h2_write32(m,entry+4,address);h2_write32(m,entry,0x19);
        h2_write32(m,connection+0x20,h2_read32(m,connection+0x20)+1);
    }
    if (*h2_ptr(m,connection+0x48,1)&32) {
        uint32_t entry=connection+0x24+h2_read32(m,connection+0x20)*8;
        h2_write32(m,entry,1);h2_write32(m,entry+4,connection+0x18);
        h2_write32(m,connection+0x20,h2_read32(m,connection+0x20)+1);
    }
    return 1;
fail:
    h2_network_connection_dispose(m,clock,send,codec,callbacks,storage_ops,connection,local,packet,storage_local,workspace);
    return 0;
}
uint32_t h2_network_connection_allocate(h2_memory *m,const h2_network_state_operations *clock,const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,const h2_network_storage_operations *storage_ops,uint32_t label,uint32_t flags,uint32_t local,uint32_t packet,uint32_t storage_local,uint8_t workspace[28]) {
    (void)label;
    if (!*h2_ptr(m,0x4d8ba0,1)) return UINT32_MAX;
    uint32_t count=h2_read32(m,0x4d87d0);
    if (!count || (count&0x80000000u)) return UINT32_MAX;
    uint32_t base=h2_read32(m,0x4d87d4);
    for (uint32_t i=0;i<count;++i) {
        uint32_t connection=base+i*0xf8;
        if (h2_read32(m,connection+0x54)) continue;
        return h2_network_connection_initialize(m,clock,send,codec,callbacks,storage_ops,connection,i,flags,0x528000,0x528b28,0x529188,0x4cf6d4,local,packet,storage_local,workspace) ? i : UINT32_MAX;
    }
    return UINT32_MAX;
}
