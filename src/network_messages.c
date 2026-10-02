#include "halo2/network_messages.h"
#include "halo2/bitstream.h"
#include "halo2/network_config.h"
#include "internal/memory.h"
#include <string.h>

static int64_t message_signed(uint32_t x) {
    return x & 0x80000000u ? (int64_t)x-INT64_C(0x100000000) : x;
}
uint8_t h2_message_writer_enqueue(h2_memory *m, const h2_network_state_operations *clock,
    const h2_socket_send_platform *send, const h2_message_codec_platform *codec,
    uint32_t writer, uint32_t address, uint32_t type, uint32_t size, uint32_t payload,
    uint32_t scratch, uint8_t address_workspace[28]) {
    if (*h2_ptr(m,writer+0x14,1)) {
        const uint8_t *a=h2_ptr(m,writer+0x62a,2), *b=h2_ptr(m,address+18,2);
        uint32_t width=a[0]|(uint32_t)a[1]<<8, other=b[0]|(uint32_t)b[1]<<8;
        if (!width || (width&0x8000) || width!=other ||
            memcmp(h2_ptr(m,writer+0x618,width),h2_ptr(m,address,width),width))
            h2_message_writer_flush(m,clock,send,writer,scratch,address_workspace);
    }
    uint32_t stream=writer+0x62c;
    for (;;) {
        uint8_t fresh=!*h2_ptr(m,writer+0x14,1);
        if (fresh) {
            h2_write32(m,stream+4,0x518);h2_write32(m,stream+12,0);
            h2_write32(m,stream+16,0);h2_write32(m,stream+24,0);*h2_ptr(m,stream+20,1)=0;
            h2_write32(m,stream,writer+0x15);h2_write32(m,stream+8,1);h2_write32(m,stream+12,1);
            memset(h2_ptr(m,writer+0x15,0x518),0,0x518);
            h2_write32(m,stream+16,0);h2_write32(m,stream+24,0);*h2_ptr(m,stream+20,1)=0;
            h2_write32(m,stream+0x2c,0);h2_write32(m,stream+0x30,0);
            for (unsigned i=0;i<20;i+=4) h2_write32(m,writer+0x618+i,h2_read32(m,address+i));
            *h2_ptr(m,writer+0x14,1)=1;
        }
        uint32_t depth=h2_read32(m,stream+24);
        h2_write32(m,stream+0x1c+depth*4,h2_read32(m,stream+16));
        h2_write32(m,stream+24,h2_read32(m,stream+24)+1);
        uint32_t position=h2_read32(m,stream+16);
        if (message_signed((h2_read32(m,stream+4)<<3)-position)>=1) {
            uint32_t byte=(uint32_t)(message_signed(position)/8);
            uint32_t shift=(uint32_t)(message_signed(position)%8)&31;
            *h2_ptr(m,h2_read32(m,stream)+byte,1)|=(uint8_t)(1u<<shift);
        }
        h2_write32(m,stream+16,h2_read32(m,stream+16)+1);
        uint32_t table=h2_read32(m,writer+12);
        h2_message_header_write(m,stream,type,size);
        codec->encode(codec->context,h2_read32(m,table+type*32+20),stream,size,payload);
        if (message_signed(h2_read32(m,stream+16)+1)<=message_signed(h2_read32(m,stream+4)<<3)) {
            h2_write32(m,stream+24,h2_read32(m,stream+24)-1);
            return 1;
        }
        h2_bitstream_pop_checkpoint(m,stream,1);
        if (fresh) return 0;
        h2_message_writer_flush(m,clock,send,writer,scratch,address_workspace);
    }
}
void h2_message_writer_flush(h2_memory *m, const h2_network_state_operations *clock,
    const h2_socket_send_platform *send, uint32_t writer, uint32_t scratch,
    uint8_t address_workspace[28]) {
    if (!*h2_ptr(m,writer+0x14,1)) return;
    uint32_t stream=writer+0x62c;
    uint32_t position=h2_read32(m,stream+0x10)+1;
    uint32_t bytes=(uint32_t)(message_signed(position+7)/8);
    h2_write32(m,stream+0x10,position);
    int64_t alignment=message_signed(h2_read32(m,stream+8));
    if (!alignment) abort();
    int64_t remainder=message_signed(bytes)%alignment;
    h2_write32(m,stream+4,bytes);
    if (remainder) h2_write32(m,stream+4,bytes+(uint32_t)alignment-(uint32_t)remainder);
    h2_write32(m,stream+12,2);
    h2_network_packet_send_datagram(m,clock,send,stream,writer+0x618,
        h2_read32(m,writer+8),0,scratch,address_workspace);
    *h2_ptr(m,writer+0x14,1)=0;
}

void h2_message_join_abort_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_write_buffer(m,stream,payload,64);
    h2_bitstream_write_buffer(m,stream,payload+8,64);
}
uint8_t h2_message_join_abort_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_read_buffer(m,stream,payload,64);
    h2_bitstream_read_buffer(m,stream,payload+8,64);
    return !h2_bitstream_has_error(m,stream);
}
/* Inlined byte-oriented flag writer; unlike the generic word writer it reads
 * the flag only when capacity remains and reloads position after the OR. */
static void message_write_flag(h2_memory *m, uint32_t stream, uint32_t flag) {
    uint32_t position=h2_read32(m,stream+16);
    if (message_signed((h2_read32(m,stream+4)<<3)-position)>=1 && *h2_ptr(m,flag,1)) {
        uint32_t byte=(uint32_t)(message_signed(position)/8);
        uint32_t shift=(uint32_t)(message_signed(position)%8)&31;
        *h2_ptr(m,h2_read32(m,stream)+byte,1)|=(uint8_t)(1u<<shift);
    }
    h2_write32(m,stream+16,h2_read32(m,stream+16)+1);
}
void h2_message_handle_ping(h2_memory *m, const h2_network_state_operations *clock,
    const h2_socket_send_platform *send, const h2_message_codec_platform *codec,
    uint32_t handler, uint32_t address, uint32_t ping, uint32_t reply,
    uint32_t packet_scratch, uint8_t address_workspace[28]) {
    const uint8_t *p=h2_ptr(m,ping,2);
    uint32_t identifier=p[0]|(uint32_t)p[1]<<8;
    uint32_t timestamp=h2_read32(m,ping+4);
    uint8_t *out=h2_ptr(m,reply,2);out[0]=(uint8_t)identifier;out[1]=(uint8_t)(identifier>>8);
    h2_write32(m,reply+4,timestamp);
    uint32_t writer=h2_read32(m,handler+12);
    h2_write32(m,reply+8,2);
    (void)h2_message_writer_enqueue(m,clock,send,codec,writer,address,1,12,reply,packet_scratch,address_workspace);
}

void h2_message_join_request_write(h2_memory *m, uint32_t s, uint32_t size, uint32_t p) {
    (void)size;
    const uint8_t *head=h2_ptr(m,p,2);
    h2_bitstream_write_bits(m,s,head[0]|(uint32_t)head[1]<<8,16);
    h2_bitstream_write_buffer(m,s,p+4,64);
    h2_bitstream_write_buffer(m,s,p+0x18c,64);
    h2_bitstream_write_buffer(m,s,p+0x150,64);
    h2_bitstream_write_buffer(m,s,p+0x194,288);
    h2_bitstream_write_bits(m,s,h2_read32(m,p+12),5);
    for (uint32_t i=0;message_signed(i)<message_signed(h2_read32(m,p+12));++i) {
        h2_bitstream_write_buffer(m,s,p+16+i*12,96);
        h2_bitstream_write_bits(m,s,h2_read32(m,p+0xd0+i*4)+1,8);
        h2_bitstream_write_bits(m,s,h2_read32(m,p+0x110+i*4)+1,31);
    }
    message_write_flag(m,s,p+0x158);
    if (*h2_ptr(m,p+0x158,1)) h2_bitstream_write_buffer(m,s,p+0x15c,32);
    h2_bitstream_write_bits(m,s,h2_read32(m,p+0x160),2);
    if (h2_read32(m,p+0x160)==2) {
        for (uint32_t i=0;i<3;++i) h2_bitstream_write_bits(m,s,h2_read32(m,p+0x174+i*4),7);
        h2_bitstream_write_buffer(m,s,p+0x164,32);
        h2_bitstream_write_buffer(m,s,p+0x168,32);
        h2_bitstream_write_buffer(m,s,p+0x170,32);
        h2_bitstream_write_buffer(m,s,p+0x16c,32);
        uint8_t present=memcmp(h2_ptr(m,p+0x180,12),h2_ptr(m,0x440070,12),12)!=0;
        uint32_t position=h2_read32(m,s+16);
        if (message_signed((h2_read32(m,s+4)<<3)-position)>=1 && present) {
            uint32_t byte=(uint32_t)(message_signed(position)/8);
            uint32_t shift=(uint32_t)(message_signed(position)%8)&31;
            *h2_ptr(m,h2_read32(m,s)+byte,1)|=(uint8_t)(1u<<shift);
        }
        h2_write32(m,s+16,h2_read32(m,s+16)+1);
        if (present) h2_bitstream_write_buffer(m,s,p+0x180,96);
    }
}
uint8_t h2_message_join_request_read(h2_memory *m, uint32_t s, uint32_t size, uint32_t p) {
    (void)size;
    uint32_t value=h2_bitstream_read_bits(m,s,16);
    uint8_t *head=h2_ptr(m,p,2);head[0]=(uint8_t)value;head[1]=(uint8_t)(value>>8);
    h2_bitstream_read_buffer(m,s,p+4,64);
    h2_bitstream_read_buffer(m,s,p+0x18c,64);
    h2_bitstream_read_buffer(m,s,p+0x150,64);
    h2_bitstream_read_buffer(m,s,p+0x194,288);
    h2_write32(m,p+12,h2_bitstream_read_bits(m,s,5));
    for (uint32_t i=0;message_signed(i)<message_signed(h2_read32(m,p+12));++i) {
        h2_bitstream_read_buffer(m,s,p+16+i*12,96);
        h2_write32(m,p+0xd0+i*4,h2_bitstream_read_bits(m,s,8)-1);
        h2_write32(m,p+0x110+i*4,h2_bitstream_read_bits(m,s,31)-1);
    }
    uint8_t flag=h2_bitstream_read_bool(m,s);*h2_ptr(m,p+0x158,1)=flag;
    if (flag) h2_bitstream_read_buffer(m,s,p+0x15c,32);
    value=h2_bitstream_read_bits(m,s,2);h2_write32(m,p+0x160,value);
    if (value==2) {
        for (uint32_t i=0;i<3;++i) h2_write32(m,p+0x174+i*4,h2_bitstream_read_bits(m,s,7));
        h2_bitstream_read_buffer(m,s,p+0x164,32);
        h2_bitstream_read_buffer(m,s,p+0x168,32);
        h2_bitstream_read_buffer(m,s,p+0x170,32);
        h2_bitstream_read_buffer(m,s,p+0x16c,32);
        if (h2_bitstream_read_bool(m,s)) h2_bitstream_read_buffer(m,s,p+0x180,96);
        else for (uint32_t i=0;i<12;i+=4) h2_write32(m,p+0x180+i,0);
    }
    return !h2_bitstream_has_error(m,s) && message_signed(h2_read32(m,p+12))>=0;
}

void h2_message_config_fields_write(h2_memory *m, uint32_t stream, uint32_t fields) {
    static const uint8_t widths[8]={5,5,5,5,3,6,6,4};
    for (uint32_t i=0;i<8;++i) {
        uint32_t value=*h2_ptr(m,fields+i,1);
        if (i<5) value=(value&0x80 ? value|0xffffff00u : value)+1;
        h2_bitstream_write_bits(m,stream,value,widths[i]);
    }
}
uint8_t h2_message_config_fields_read(h2_memory *m, uint32_t stream, uint32_t fields) {
    static const uint8_t widths[8]={5,5,5,5,3,6,6,4};
    for (uint32_t i=0;i<16;i+=4) h2_write32(m,fields+i,0);
    for (uint32_t i=0;i<8;++i) {
        uint32_t value=h2_bitstream_read_bits(m,stream,widths[i]);
        *h2_ptr(m,fields+i,1)=(uint8_t)(value-(i<5));
    }
    return h2_network_config_fields_valid(m,fields);
}

void h2_message_ping_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    const uint8_t *p=h2_ptr(m,payload,2);
    h2_bitstream_write_bits(m,stream,p[0]|(uint32_t)p[1]<<8,16);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+4),32);
    message_write_flag(m,stream,payload+8);
}

uint8_t h2_message_ping_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    uint32_t value=h2_bitstream_read_bits(m,stream,16);
    uint8_t *p=h2_ptr(m,payload,2);p[0]=(uint8_t)value;p[1]=(uint8_t)(value>>8);
    h2_write32(m,payload+4,h2_bitstream_read_bits(m,stream,32));
    *h2_ptr(m,payload+8,1)=h2_bitstream_read_bool(m,stream);
    return !h2_bitstream_has_error(m,stream);
}

void h2_message_pong_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    const uint8_t *p=h2_ptr(m,payload,2);
    h2_bitstream_write_bits(m,stream,p[0]|(uint32_t)p[1]<<8,16);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+4),32);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+8),2);
}

uint8_t h2_message_pong_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    uint32_t value=h2_bitstream_read_bits(m,stream,16);
    uint8_t *p=h2_ptr(m,payload,2);p[0]=(uint8_t)value;p[1]=(uint8_t)(value>>8);
    h2_write32(m,payload+4,h2_bitstream_read_bits(m,stream,32));
    value=h2_bitstream_read_bits(m,stream,2);
    h2_write32(m,payload+8,value);
    return !h2_bitstream_has_error(m,stream) && value<3;
}

void h2_message_broadcast_search_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    const uint8_t *p=h2_ptr(m,payload,2);
    h2_bitstream_write_bits(m,stream,p[0]|(uint32_t)p[1]<<8,16);
    h2_bitstream_write_buffer(m,stream,payload+4,64);
}

uint8_t h2_message_broadcast_search_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    uint32_t value=h2_bitstream_read_bits(m,stream,16);
    uint8_t *p=h2_ptr(m,payload,2);p[0]=(uint8_t)value;p[1]=(uint8_t)(value>>8);
    h2_bitstream_read_buffer(m,stream,payload+4,64);
    return !h2_bitstream_has_error(m,stream);
}

/* Connection writers omit only discarded local range-diagnostic text. */
void h2_message_connect_request_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+0),32);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+4),8);
}

uint8_t h2_message_connect_request_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    uint32_t value0=h2_bitstream_read_bits(m,stream,32);
    h2_write32(m,payload+0,value0);
    uint32_t value1=h2_bitstream_read_bits(m,stream,8);
    h2_write32(m,payload+4,value1);
    return !h2_bitstream_has_error(m,stream);
}

void h2_message_connect_refuse_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+0),32);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+4),3);
}

uint8_t h2_message_connect_refuse_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    uint32_t value0=h2_bitstream_read_bits(m,stream,32);
    h2_write32(m,payload+0,value0);
    uint32_t value1=h2_bitstream_read_bits(m,stream,3);
    h2_write32(m,payload+4,value1);
    return !h2_bitstream_has_error(m,stream);
}

void h2_message_connect_establish_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+0),32);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+4),32);
}

uint8_t h2_message_connect_establish_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    uint32_t value0=h2_bitstream_read_bits(m,stream,32);
    h2_write32(m,payload+0,value0);
    uint32_t value1=h2_bitstream_read_bits(m,stream,32);
    h2_write32(m,payload+4,value1);
    return !h2_bitstream_has_error(m,stream);
}

void h2_message_connect_closed_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+0),32);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+4),32);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+8),5);
}

uint8_t h2_message_connect_closed_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    uint32_t value0=h2_bitstream_read_bits(m,stream,32);
    h2_write32(m,payload+0,value0);
    uint32_t value1=h2_bitstream_read_bits(m,stream,32);
    h2_write32(m,payload+4,value1);
    uint32_t value2=h2_bitstream_read_bits(m,stream,5);
    h2_write32(m,payload+8,value2);
    return !h2_bitstream_has_error(m,stream) && value2<18;
}

uint32_t h2_message_session_lookup(h2_memory *m, uint32_t sessions, uint32_t identity) {
    for (uint32_t i=0;i<3;++i) {
        uint32_t session=h2_read32(m,sessions+i*4);
        if (session && h2_read32(m,session+0x741c) && *h2_ptr(m,session+0x24,1)) {
            uint32_t low=h2_read32(m,session+0x1c), high=h2_read32(m,session+0x20);
            if (low==h2_read32(m,identity) && high==h2_read32(m,identity+4))
                return h2_read32(m,sessions+i*4);
        }
    }
    return 0;
}
uint32_t h2_message_session_time(h2_memory *m, const h2_network_state_operations *clock, uint32_t identity) {
    uint32_t sessions=h2_read32(m,0x510550);
    if (!sessions) return 0;
    uint32_t session=h2_message_session_lookup(m,sessions,identity);
    if (!session || !*h2_ptr(m,session+0x78ac,1)) return 0;
    uint32_t now=clock->ticks(clock->context);
    return now+h2_read32(m,session+0x78b0);
}
void h2_message_time_sync_write(h2_memory *m, const h2_network_state_operations *clock,
    uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_write_buffer(m,stream,payload,64);
    const uint8_t *p=h2_ptr(m,payload+24,2);
    h2_bitstream_write_bits(m,stream,p[0]|(uint32_t)p[1]<<8,1);
    p=h2_ptr(m,payload+24,2);
    uint32_t now;
    if (p[0] || p[1]) {
        now=h2_message_session_time(m,clock,payload);
        h2_bitstream_write_bits(m,stream,h2_read32(m,payload+8),32);
        h2_bitstream_write_bits(m,stream,h2_read32(m,payload+16),32);
    } else now=clock->ticks(clock->context);
    h2_bitstream_write_bits(m,stream,now,32);
}
uint8_t h2_message_time_sync_read(h2_memory *m, const h2_network_state_operations *clock,
    uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_read_buffer(m,stream,payload,64);
    uint32_t mode=h2_bitstream_read_bits(m,stream,1);
    uint8_t *p=h2_ptr(m,payload+24,2);p[0]=(uint8_t)mode;p[1]=(uint8_t)(mode>>8);
    if (h2_bitstream_has_error(m,stream) || (mode&0xffff)>=2) return 0;
    h2_write32(m,payload+8,h2_bitstream_read_bits(m,stream,32));
    if (mode&0xffff) {
        h2_write32(m,payload+12,clock->ticks(clock->context));
        h2_write32(m,payload+16,h2_bitstream_read_bits(m,stream,32));
        h2_write32(m,payload+20,h2_bitstream_read_bits(m,stream,32));
    } else {
        h2_write32(m,payload+12,0xffffffff);
        uint32_t now=h2_message_session_time(m,clock,payload);
        h2_write32(m,payload+20,0xffffffff);
        h2_write32(m,payload+16,now);
    }
    /* The original does not recheck overflow after the timestamp fields. */
    return 1;
}
uint8_t h2_message_time_sync_clear(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)stream;(void)size;
    for (uint32_t i=8;i<24;i+=4) h2_write32(m,payload+i,0xffffffff);
    return 1;
}

void h2_message_election_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_write_buffer(m,stream,payload,64);
    h2_bitstream_write_buffer(m,stream,payload+8,288);
    h2_bitstream_write_buffer(m,stream,payload+44,288);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+80),32);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+84),4);
    h2_bitstream_write_buffer(m,stream,payload+88,32);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+92),5);
    /* Count is reloaded after each entry; original range diagnostics only
     * produce discarded stack text and do not clamp the loop. */
    for (uint32_t i=0;message_signed(i)<message_signed(h2_read32(m,payload+92));++i)
        h2_bitstream_write_buffer(m,stream,payload+96+i*6,48);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+192),16);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+196),16);
}
uint8_t h2_message_election_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_read_buffer(m,stream,payload,64);
    h2_bitstream_read_buffer(m,stream,payload+8,288);
    h2_bitstream_read_buffer(m,stream,payload+44,288);
    h2_write32(m,payload+80,h2_bitstream_read_bits(m,stream,32));
    h2_write32(m,payload+84,h2_bitstream_read_bits(m,stream,4));
    h2_bitstream_read_buffer(m,stream,payload+88,32);
    uint32_t count=h2_bitstream_read_bits(m,stream,5);
    h2_write32(m,payload+92,count);
    uint8_t valid=count<=16;
    if (valid)
        for (uint32_t i=0;message_signed(i)<message_signed(h2_read32(m,payload+92));++i)
            h2_bitstream_read_buffer(m,stream,payload+96+i*6,48);
    h2_write32(m,payload+192,h2_bitstream_read_bits(m,stream,16));
    uint32_t last=h2_bitstream_read_bits(m,stream,16);
    h2_write32(m,payload+196,last);
    if (!valid || h2_bitstream_has_error(m,stream)) return 0;
    count=h2_read32(m,payload+92);
    if (count<32 && ((h2_read32(m,payload+192)>>count) || (last>>count))) return 0;
    return 1;
}
void h2_message_election_refuse_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_write_buffer(m,stream,payload,64);
    h2_bitstream_write_bits(m,stream,h2_read32(m,payload+8),4);
    message_write_flag(m,stream,payload+12);
    if (*h2_ptr(m,payload+12,1)) h2_bitstream_write_buffer(m,stream,payload+13,288);
}
uint8_t h2_message_election_refuse_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_read_buffer(m,stream,payload,64);
    h2_write32(m,payload+8,h2_bitstream_read_bits(m,stream,4));
    uint8_t flag=h2_bitstream_read_bool(m,stream);
    *h2_ptr(m,payload+12,1)=flag;
    if (flag) h2_bitstream_read_buffer(m,stream,payload+13,288);
    if (h2_bitstream_has_error(m,stream)) return 0;
    uint32_t reason=h2_read32(m,payload+8);
    return message_signed(reason)>0 && message_signed(reason)<11;
}

void h2_message_host_decline_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_write_buffer(m,stream,payload,64);
    message_write_flag(m,stream,payload+8);
    if (*h2_ptr(m,payload+8,1)) {
        message_write_flag(m,stream,payload+9);
        message_write_flag(m,stream,payload+10);
        if (*h2_ptr(m,payload+10,1)) h2_bitstream_write_buffer(m,stream,payload+12,288);
    }
}
uint8_t h2_message_host_decline_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_read_buffer(m,stream,payload,64);
    uint8_t flag=h2_bitstream_read_bool(m,stream);
    *h2_ptr(m,payload+8,1)=flag;
    if (flag) {
        flag=h2_bitstream_read_bool(m,stream);*h2_ptr(m,payload+9,1)=flag;
        flag=h2_bitstream_read_bool(m,stream);*h2_ptr(m,payload+10,1)=flag;
        if (flag) h2_bitstream_read_buffer(m,stream,payload+12,288);
    }
    return !h2_bitstream_has_error(m,stream);
}

void h2_message_session_id_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_write_buffer(m, stream, payload, 64);
}
uint8_t h2_message_leave_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_read_buffer(m, stream, payload, 64);
    return !h2_bitstream_has_error(m, stream);
}
uint8_t h2_message_session_control_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_read_buffer(m, stream, payload, 64);
    return !h2_bitstream_has_error(m, stream);
}
void h2_message_handoff_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_write_buffer(m, stream, payload, 64);
    const uint8_t *p=h2_ptr(m,payload+44,2);
    uint32_t value=p[0]|(uint32_t)p[1]<<8;
    if (value&0x8000) value|=0xffff0000u;
    /* The original formats an unused local diagnostic for values >= 16. */
    h2_bitstream_write_bits(m, stream, value, 4);
    h2_bitstream_write_buffer(m, stream, payload+8, 288);
}
uint8_t h2_message_handoff_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_read_buffer(m, stream, payload, 64);
    uint32_t value=h2_bitstream_read_bits(m, stream, 4);
    uint8_t *p=h2_ptr(m,payload+44,2);
    p[0]=(uint8_t)value;p[1]=(uint8_t)(value>>8);
    h2_bitstream_read_buffer(m, stream, payload+8, 288);
    return !h2_bitstream_has_error(m, stream);
}

void h2_message_join_refuse_write(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_write_buffer(m, stream, payload, 64);
    /* The original's range diagnostic is discarded local stack text. */
    h2_bitstream_write_bits(m, stream, h2_read32(m, payload+8), 4);
}
uint8_t h2_message_join_refuse_read(h2_memory *m, uint32_t stream, uint32_t size, uint32_t payload) {
    (void)size;
    h2_bitstream_read_buffer(m, stream, payload, 64);
    h2_write32(m, payload+8, h2_bitstream_read_bits(m, stream, 4));
    return !h2_bitstream_has_error(m, stream);
}

void h2_message_header_write(h2_memory *m, uint32_t stream, uint32_t type, uint32_t size) {
    /* Out-of-range diagnostics in the original only format an unused local
     * stack string. Encoding proceeds with the same low-bit truncation. */
    h2_bitstream_write_bits(m, stream, type, 8);
    h2_bitstream_write_bits(m, stream, size, 16);
}
uint8_t h2_message_header_read(h2_memory *m, uint32_t stream, uint32_t type_output,
    uint32_t table, uint32_t size_output) {
    h2_write32(m, type_output, h2_bitstream_read_bits(m, stream, 8));
    uint32_t size = h2_bitstream_read_bits(m, stream, 16);
    h2_write32(m, size_output, size);
    if (h2_bitstream_has_error(m, stream)) return 0;
    uint32_t type = h2_read32(m, type_output);
    if (type >= 45) return 0;
    uint32_t descriptor = table+type*32;
    if (!*h2_ptr(m, descriptor, 1)) return 0;
    if ((size ^ 0x80000000u) < (h2_read32(m, descriptor+12) ^ 0x80000000u) ||
        (size ^ 0x80000000u) > (h2_read32(m, descriptor+16) ^ 0x80000000u)) return 0;
    return !h2_bitstream_has_error(m, stream);
}

/* Reviewed constant registrations; extraction/disassembly evidence lives in
 * config/message_descriptors.json. No original x86 is executed at runtime. */
static const uint32_t descriptors[45][7]={
    {0x452c60,0x0,0xc,0xc,0xac490,0xac530,0x0}, /* 0: ping */
    {0x452c58,0x0,0xc,0xc,0xac580,0xac610,0x0}, /* 1: pong */
    {0x452c44,0x0,0xc,0xc,0xac670,0xac6e0,0x0}, /* 2: broadcast-search */
    {0x452c34,0x0,0x720,0x720,0xac730,0xac7a0,0x0}, /* 3: broadcast-reply */
    {0x452ca8,0x0,0x8,0x8,0xac8a0,0xac900,0x0}, /* 4: connect-request */
    {0x452c8c,0x0,0x8,0x8,0xac940,0xac9a0,0x0}, /* 5: connect-refuse */
    {0x452c78,0x0,0x8,0x8,0xac9e0,0xaca00,0x0}, /* 6: connect-establish */
    {0x452c68,0x0,0xc,0xc,0xaca40,0xacab0,0x0}, /* 7: connect-closed */
    {0x452dbc,0x0,0x1b8,0x1b8,0xacc20,0xacfa0,0x0}, /* 8: join-request */
    {0x452db0,0x0,0x10,0x10,0xad1c0,0xad1e0,0x0}, /* 9: join-abort */
    {0x452da4,0x0,0xc,0xc,0xad230,0xad290,0x0}, /* 10: join-refuse */
    {0x452d94,0x0,0x8,0x8,0xad5a0,0xad2e0,0x0}, /* 11: leave-session */
    {0x452d80,0x0,0x8,0x8,0xad5a0,0xad2e0,0x0}, /* 12: leave-acknowledge */
    {0x452d70,0x0,0x8,0x8,0xad5a0,0xad3f0,0x0}, /* 13: session-disband */
    {0x452d60,0x0,0x8,0x8,0xad5a0,0xad3f0,0x0}, /* 14: session-boot */
    {0x452d50,0x0,0x2e,0x2e,0xad320,0xad390,0x0}, /* 15: host-handoff */
    {0x452d40,0x0,0x2e,0x2e,0xad320,0xad390,0x0}, /* 16: peer-handoff */
    {0x452d30,0x0,0x8,0x8,0xad5a0,0xad3f0,0x0}, /* 17: host-transition */
    {0x452d1c,0x0,0x8,0x8,0xad5a0,0xad3f0,0x0}, /* 18: host-reestablish */
    {0x452d0c,0x0,0x30,0x30,0xad430,0xad530,0x0}, /* 19: host-decline */
    {0x452cf8,0x0,0x8,0x8,0xad5a0,0xad3f0,0x0}, /* 20: peer-reestablish */
    {0x452ce8,0x0,0x8,0x8,0xad5a0,0xad3f0,0x0}, /* 21: peer-establish */
    {0x452cdc,0x0,0xc8,0xc8,0xad5c0,0xad710,0x0}, /* 22: election */
    {0x452ccc,0x0,0x34,0x34,0xad820,0xad8d0,0x0}, /* 23: election-refuse */
    {0x452cb8,0x0,0x1c,0x1c,0xad940,0xad9e0,0xada90}, /* 24: time-synchronize */
    {0x452e40,0x0,0x489c,0x489c,0xadef0,0xae7f0,0x0}, /* 25: membership-update */
    {0x452e30,0x0,0xd0,0xd0,0xaedb0,0xaf050,0x0}, /* 26: peer-properties */
    {0x452e1c,0x0,0x2c,0x2c,0xaf1f0,0xaf220,0x0}, /* 27: delegate-leadership */
    {0x452e0c,0x0,0x2c,0x2c,0xaf1f0,0xaf220,0x0}, /* 28: boot-machine */
    {0x452e00,0x0,0xb0,0xb0,0xaf270,0xaf320,0x0}, /* 29: player-add */
    {0x452df0,0x0,0x18,0x18,0xaf3c0,0xaf430,0x0}, /* 30: player-refuse */
    {0x452de0,0x0,0xc,0xc,0xaf490,0xaf4f0,0x0}, /* 31: player-remove */
    {0x452dcc,0x0,0xa4,0xa4,0xaf540,0xaf5f0,0x0}, /* 32: player-properties */
    {0x452e8c,0x0,0x14d8,0x14d8,0xaf890,0xb0900,0x0}, /* 33: parameters-update */
    {0x452e68,0x0,0x59c,0x59c,0xb14a0,0xb1c80,0x0}, /* 34: parameters-request */
    {0x452e7c,0x0,0x20,0x20,0xb1fd0,0xb20c0,0x0}, /* 35: countdown-timer */
    {0x452e54,0x0,0x10,0x10,0xb2140,0xb21b0,0x0}, /* 36: mode-acknowledge */
    {0x452eb4,0x0,0x8,0x8,0xb2440,0xb24e0,0x0}, /* 37: view-establishment */
    {0x452ea0,0x0,0xc8,0xc8,0xb2550,0xb2600,0x0}, /* 38: player-acknowledge */
    {0x452f08,0x0,0x4048,0x4048,0xb2710,0xb2730,0xb2770}, /* 39: synchronous-update */
    {0x452ef4,0x0,0x180,0x180,0xb2790,0xb2860,0xb2920}, /* 40: synchronous-actions */
    {0x452ee0,0x0,0x4,0x4,0xb2980,0xb29a0,0x0}, /* 41: synchronous-join */
    {0x452ec8,0x1,0x8,0xffff,0xb29e0,0xb2a90,0x0}, /* 42: synchronous-gamestate */
    {0x452f1c,0x0,0x4fb8,0x4fb8,0xb2c50,0xb2c80,0x0}, /* 43: game-results */
    {0x452f2c,0x0,0x8,0x8,0xb2d10,0xb2da0,0x0}, /* 44: test */
};
static void register_range(h2_memory *m,uint32_t table,unsigned first,unsigned count) {
    for (unsigned i=first;i<first+count;i++) {
        uint32_t record=table+i*32;
        for (unsigned j=0;j<7;j++) h2_write32(m,record+4+j*4,descriptors[i][j]);
        *h2_ptr(m,record,1)=1;
    }
}
void h2_messages_register_discovery(h2_memory *m,uint32_t table) { register_range(m,table,0,4); }
void h2_messages_register_connection(h2_memory *m,uint32_t table) { register_range(m,table,4,4); }
void h2_messages_register_session(h2_memory *m,uint32_t table) { register_range(m,table,8,17); }
void h2_messages_register_membership(h2_memory *m,uint32_t table) { register_range(m,table,25,8); }
void h2_messages_register_parameters(h2_memory *m,uint32_t table) { register_range(m,table,33,4); }
void h2_messages_register_simulation(h2_memory *m,uint32_t table) { register_range(m,table,37,2); }
void h2_messages_register_synchronous(h2_memory *m,uint32_t table) { register_range(m,table,39,4); }
void h2_messages_register_results(h2_memory *m,uint32_t table) { register_range(m,table,43,1); }
void h2_messages_register_test(h2_memory *m,uint32_t table) { register_range(m,table,44,1); }

void h2_message_writer_flush_address(h2_memory *m,const h2_network_state_operations *clock,
    const h2_socket_send_platform *send,uint32_t writer,uint32_t address,uint32_t scratch,uint8_t workspace[28]) {
    if (!*h2_ptr(m,writer+0x14,1)) return;
    const uint8_t *a=h2_ptr(m,writer+0x62a,2),*b=h2_ptr(m,address+18,2);
    uint32_t width=a[0]|(uint32_t)a[1]<<8,other=b[0]|(uint32_t)b[1]<<8;
    if (width && !(width&0x8000) && width==other &&
        !memcmp(h2_ptr(m,writer+0x618,width),h2_ptr(m,address,width),width))
        h2_message_writer_flush(m,clock,send,writer,scratch,workspace);
}
