#include "halo2/network_cleanup.h"
#include "internal/memory.h"
void h2_network_connections_dispose(h2_memory *m,const h2_network_state_operations *clock,
    const h2_socket_send_platform *send,const h2_message_codec_platform *codec,const h2_connection_callbacks *callbacks,
    const h2_network_registration_platform *registration,const h2_observer_events *events,const h2_network_storage_operations *storage,
    const h2_network_cleanup_platform *platform,uint32_t local,uint32_t packet,uint32_t storage_scratch,uint8_t workspace[28]) {
    h2_network_observer_close_connections(m,clock,send,codec,callbacks,registration,events,storage,0x5291a0,local,packet,storage_scratch,workspace);
    uint32_t object=h2_read32(m,0x4d87e8);
    if (object) {
        h2_write32(m,object+0xa0ac,0x450cb8);h2_write32(m,object+0x2098,0x450d60);
        h2_write32(m,0x4d87e8,0);
    }
    object=h2_read32(m,0x4d87f0);
    if (object) {*h2_ptr(m,object+0x29,1)=0;h2_write32(m,0x4d87f0,0);}
    object=h2_read32(m,0x4d87ec);
    if (object) {*h2_ptr(m,object+0x29,1)=0;h2_write32(m,0x4d87ec,0);}
    for (uint32_t i=0;i<3;++i) if (h2_read32(m,0x4d87d4+i*4)) h2_write32(m,0x4d87d4+i*4,0);
    uint32_t wrapper=h2_read32(m,0x4d87f8);
    if (wrapper) {
        object=h2_read32(m,wrapper);
        if (object) {
            uint32_t function=h2_read32(m,h2_read32(m,object)+0x34);
            platform->destroy_provider(platform->context,function,object,1);
            h2_write32(m,wrapper,0);
        }
        platform->free_wrapper(platform->context,wrapper);
        h2_write32(m,0x4d87f8,0);
    }
    if (h2_read32(m,0x4d87fc)) h2_write32(m,0x4d87fc,0);
    h2_write32(m,0x4d87d0,0);h2_write32(m,0x4d87e0,0);*h2_ptr(m,0x4d87e4,1)=0;
    h2_write32(m,0x4d87c4,0);h2_write32(m,0x4d87c8,0);h2_write32(m,0x4d87cc,0);
}
