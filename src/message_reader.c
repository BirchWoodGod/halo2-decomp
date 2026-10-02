#include "halo2/message_reader.h"
#include "halo2/network_messages.h"
#include "halo2/bitstream.h"
#include "internal/memory.h"
#include <string.h>
uint8_t h2_message_reader_process(h2_memory *m,const h2_message_reader_operations *ops,
    uint32_t owner,uint32_t address,uint32_t stream,uint32_t scratch) {
    h2_write32(m,stream+12,3);
    h2_write32(m,stream+16,0);
    h2_write32(m,stream+24,0);
    *h2_ptr(m,stream+20,1)=0;
    if (h2_bitstream_read_bits(m,stream,32)==0x64656267) *h2_ptr(m,stream+20,1)=1;
    else {
        h2_write32(m,stream+16,0);
        *h2_ptr(m,stream+20,1)=0;
    }
    if (h2_bitstream_has_error(m,stream)) return 0;
    uint8_t last=1;
    for (;;) {
        if (!h2_bitstream_read_bool(m,stream)) {
            h2_write32(m,stream+12,5);
            return last;
        }
        uint32_t table=h2_read32(m,owner+12);
        h2_write32(m,scratch,0xffffffff);
        h2_write32(m,scratch+4,0);
        if (!h2_message_header_read(m,stream,scratch,table,scratch+4)) return 0;
        uint32_t size=h2_read32(m,scratch+4),payload=scratch+8;
        memset(h2_ptr(m,payload,size),0,size);
        uint32_t type=h2_read32(m,scratch);
        last=ops->decode(ops->context,h2_read32(m,table+type*32+24),stream,size,payload);
        if (!last) return 0;
        uint32_t handler=h2_read32(m,owner+16);
        if (handler) ops->deliver(ops->context,handler,h2_read32(m,scratch),payload,address);
    }
}
