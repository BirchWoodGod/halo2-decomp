#include "halo2/network_membership_snapshot.h"
#include "halo2/network_peer_changes.h"
#include "internal/memory.h"
#include <string.h>
static int64_t sv(uint32_t v) {return v&UINT32_C(0x80000000) ? (int64_t)v-INT64_C(0x100000000) : v;}
static void copy(h2_memory *m,uint32_t d,uint32_t s,uint32_t n) {memcpy(h2_ptr(m,d,n),h2_ptr(m,s,n),n);}
static int different(h2_memory *m,uint32_t a,uint32_t b,uint32_t n) {return memcmp(h2_ptr(m,a,n),h2_ptr(m,b,n),n)!=0;}
static void word(h2_memory *m,uint32_t p,uint32_t v) {uint8_t *x=h2_ptr(m,p,2);x[0]=(uint8_t)v;x[1]=(uint8_t)(v>>8);}
static uint32_t entry(h2_memory *m,uint32_t out,uint32_t counter,uint32_t offset,uint32_t size) {
    uint8_t *x=h2_ptr(m,out+counter,2);uint32_t n=x[0]|(uint32_t)x[1]<<8;word(m,out+counter,n+1);
    return out+offset+n*size;
}
void h2_network_membership_snapshot(h2_memory *m,uint32_t session,uint32_t c,uint32_t b,uint32_t out) {
    uint32_t old_to_new[16],new_to_old[16];
    for(uint32_t i=0;i<16;++i) old_to_new[i]=new_to_old[i]=UINT32_MAX;
    memset(h2_ptr(m,out,0x489c),0,0x489c);copy(m,out,session+0x1c,8);copy(m,out+8,c,4);
    h2_write32(m,out+12,b ? h2_read32(m,b) : UINT32_MAX);
    if(b) {
        uint32_t old_count=h2_read32(m,b+8),new_count=h2_read32(m,c+8);
        for(uint32_t i=0;sv(i)<sv(old_count);++i) for(uint32_t j=0;sv(j)<sv(new_count);++j)
            if(!different(m,b+12+i*0x10c,c+12+j*0x10c,36)) {old_to_new[i]=j;new_to_old[j]=i;}
        for(uint32_t i=0;sv(i)<sv(h2_read32(m,b+8));++i) if(old_to_new[i]==UINT32_MAX) {
            uint32_t e=entry(m,out,0x10,0x14,0x104);word(m,e,i);word(m,e+2,UINT32_MAX);copy(m,e+4,b+12+i*0x10c,36);
        }
    }
    for(uint32_t i=0;sv(i)<sv(h2_read32(m,c+8));++i) {
        uint32_t p=c+12+i*0x10c,j=new_to_old[i];
        uint32_t old=j==UINT32_MAX ? 0 : b+12+j*0x10c;
        int change=!old || *h2_ptr(m,p+0x24,1)!=*h2_ptr(m,old+0x24,1) || different(m,p+0x28,old+0x28,0xc8);
        if(change || i!=j) {
            uint32_t e=entry(m,out,0x10,0x14,0x104);word(m,e,j);word(m,e+2,i);copy(m,e+4,p,36);
            if(change) {
                *h2_ptr(m,e+0x28,1)=1;copy(m,e+0x29,p+0x24,1);
                h2_network_peer_changes(m,p+0x28,old ? old+0x28 : 0,e+0x2c);
            }
        }
    }
    uint32_t retained=0;
    if(b) for(uint32_t i=0;i<16;++i) {
        uint32_t bit=UINT32_C(1)<<i,old=b+0x10d4+i*0x13c,p=c+0x10d4+i*0x13c;
        if(!(h2_read32(m,b+0x10d0)&bit)) continue;
        uint32_t owner=h2_read32(m,old+12),mapped=old_to_new[owner];
        if((h2_read32(m,c+0x10d0)&bit) && !different(m,old,p,12) && mapped!=UINT32_MAX && h2_read32(m,p+12)==mapped && h2_read32(m,p+16)==h2_read32(m,old+16)) retained|=bit;
        else if(mapped!=UINT32_MAX) {uint32_t e=entry(m,out,0x12,0x2094,0x140);word(m,e,i);}
    }
    for(uint32_t i=0;i<16;++i) {
        uint32_t bit=UINT32_C(1)<<i,p=c+0x10d4+i*0x13c,old=b+0x10d4+i*0x13c;
        if(!(h2_read32(m,c+0x10d0)&bit)) continue;
        int exists=(retained&bit)!=0;
        if(exists && h2_read32(m,p+20)==h2_read32(m,old+20) && !different(m,p+24,old+24,0x90) && !different(m,p+0xa8,old+0xa8,0x90) && h2_read32(m,p+0x138)==h2_read32(m,old+0x138)) continue;
        uint32_t e=entry(m,out,0x12,0x2094,0x140);word(m,e,i);word(m,e+2,exists ? 2 : 1);
        if(!exists) {copy(m,e+4,p,12);word(m,e+16,h2_read32(m,p+12));word(m,e+18,h2_read32(m,p+16));}
        if(h2_read32(m,p+20)!=UINT32_MAX) {
            *h2_ptr(m,e+20,1)=1;copy(m,e+24,p+20,4);copy(m,e+28,p+24,0x90);copy(m,e+0xac,p+0xa8,0x90);copy(m,e+0x13c,p+0x138,4);
        }
    }
    if(!b || h2_read32(m,c+4)!=h2_read32(m,b+4)) {*h2_ptr(m,out+0x4894,1)=1;copy(m,out+0x4898,c+4,4);}
}
