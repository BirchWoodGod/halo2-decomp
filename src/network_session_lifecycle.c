#include "halo2/network_session_lifecycle.h"
#include "internal/memory.h"
#include <string.h>
static int64_t signed32(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
static void copy_words(h2_memory *m,uint32_t dst,uint32_t src,uint32_t count) {
    for (uint32_t i=0;i<count;++i) h2_write32(m,dst+i*4,h2_read32(m,src+i*4));
}
void h2_network_session_detach_peer(h2_memory *m,uint32_t session,uint32_t index) {
    uint32_t peer=session+0x72dc+index*20;
    /* The original state-dependent peer scan has no persistent result. */
    uint32_t slot=h2_read32(m,peer+4);
    if (slot!=UINT32_MAX) {
        uint32_t observer=h2_read32(m,session+8)+0xa8+slot*0x528;
        uint8_t bit=(uint8_t)(UINT32_C(1)<<(h2_read32(m,session+0x10)&31));
        *h2_ptr(m,observer+9,1)&=(uint8_t)~bit;
        h2_write32(m,peer+4,UINT32_MAX);
    }
    for (uint32_t i=0;i<5;++i) h2_write32(m,peer+i*4,0);
    h2_write32(m,peer+4,UINT32_MAX);
}
void h2_network_session_release_registration(h2_memory *m,const h2_session_registration_platform *p,uint32_t session) {
    if (!*h2_ptr(m,session+0x24,1)) return;
    if (*h2_ptr(m,0x4cf8d4,1)) (void)p->session_release(p->context,session+0x1c,0,0,0,16);
    uint32_t key=0x4cf7d4+h2_read32(m,session+0x38)*32;
    if (*h2_ptr(m,key,1)) {
        (void)p->key_release(p->context,key+8);*h2_ptr(m,key,1)=0;
    }
    uint32_t index=h2_read32(m,session+0x10),observer=h2_read32(m,session+8);
    h2_write32(m,observer+index*36+0x18,UINT32_MAX);
    h2_write32(m,session+0x1c,0);h2_write32(m,session+0x20,0);
    for (uint32_t i=0;i<4;++i) h2_write32(m,session+0x25+i*4,0);
    h2_write32(m,session+0x3c,UINT32_MAX);*h2_ptr(m,session+0x24,1)=0;
}
void h2_network_session_update_join_abort(h2_memory *m,const h2_network_state_operations *clock,const h2_socket_send_platform *send,const h2_message_codec_platform *codec,uint32_t session,uint32_t local,uint32_t packet,uint8_t workspace[28]) {
    uint8_t override=*h2_ptr(m,0x510548,1);
    uint32_t previous=h2_read32(m,session+0x748c);
    uint32_t now=override ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    if (signed32(now-previous)<=signed32(h2_read32(m,0x4cf4a0))) return;
    uint32_t high=h2_read32(m,session+0x20),low=h2_read32(m,session+0x1c);
    memset(h2_ptr(m,local,16),0,16);h2_write32(m,local+4,high);
    uint32_t a=h2_read32(m,session+0x747c);
    h2_write32(m,local,low);uint32_t b=h2_read32(m,session+0x7480);
    h2_write32(m,local+8,a);h2_write32(m,local+12,b);
    (void)h2_message_writer_enqueue(m,clock,send,codec,h2_read32(m,session+4),session+0x7444,9,16,local,packet,workspace);
    now=*h2_ptr(m,0x510548,1) ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    h2_write32(m,session+0x748c,now);
}
void h2_network_session_begin_join_abort(h2_memory *m,const h2_network_state_operations *clock,const h2_socket_send_platform *send,const h2_message_codec_platform *codec,uint32_t session,uint32_t saved,uint32_t local,uint32_t packet,uint8_t workspace[28]) {
    memset(h2_ptr(m,saved,112),0,112);
    copy_words(m,saved,session+0x7424,9);copy_words(m,saved+36,session+0x7448,5);
    uint32_t c=h2_read32(m,session+0x7608),b=h2_read32(m,session+0x75e0);
    copy_words(m,saved+56,session+0x75e4,9);
    uint32_t a=h2_read32(m,session+0x75dc);h2_write32(m,saved+100,c);
    uint8_t override=*h2_ptr(m,0x510548,1);
    h2_write32(m,saved+92,a);h2_write32(m,saved+96,b);
    uint32_t now=override ? h2_read32(m,0x51054c) : clock->ticks(clock->context);
    h2_write32(m,saved+104,now);
    h2_write32(m,session+0x7650,h2_read32(m,session+0x7650)+1);
    memset(h2_ptr(m,session+0x761c,52),0,52);
    h2_write32(m,session+0x7654,UINT32_MAX);h2_write32(m,session+0x7658,UINT32_MAX);
    memset(h2_ptr(m,session+0x4978,0x14b0),0,0x14b0);h2_write32(m,session+0x4978,UINT32_MAX);
    memset(h2_ptr(m,session+0x4c,0x2494),0,0x2494);h2_write32(m,session+0x4c,UINT32_MAX);
    h2_write32(m,session+0x40,UINT32_MAX);
    for (uint32_t i=0;i<16;++i) if (*h2_ptr(m,session+0x72dc+i*20,1)) h2_network_session_detach_peer(m,session,i);
    h2_write32(m,session+0x72d8,UINT32_MAX);
    memset(h2_ptr(m,session+0x7420,0x1f8),0,0x1f8);copy_words(m,session+0x7420,saved,28);
    h2_write32(m,session+0x741c,2);
    h2_network_session_update_join_abort(m,clock,send,codec,session,local,packet,workspace);
}
