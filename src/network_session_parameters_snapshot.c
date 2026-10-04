#include "halo2/network_session_parameters_snapshot.h"
#include "internal/memory.h"
#include <string.h>
static int changed(h2_memory *m,uint32_t c,uint32_t b,uint32_t off,uint32_t n) {
    return !b || memcmp(h2_ptr(m,c+off,n),h2_ptr(m,b+off,n),n)!=0;
}
static void copy(h2_memory *m,uint32_t out,uint32_t in,uint32_t n) {
    memcpy(h2_ptr(m,out,n),h2_ptr(m,in,n),n);
}
static void flag(h2_memory *m,uint32_t out,uint32_t off) {*h2_ptr(m,out+off,1)=1;}
static int text_changed(h2_memory *m,uint32_t a,uint32_t b,uint32_t count,uint32_t width) {
    for(uint32_t i=0;i<count;++i) {
        uint8_t *x=h2_ptr(m,a+i*width,width),*y=h2_ptr(m,b+i*width,width);
        if(memcmp(x,y,width)) return 1;
        if(!x[0] && (width==1 || !x[1])) break;
    }
    return 0;
}
static void text_copy(h2_memory *m,uint32_t out,uint32_t in,uint32_t count,uint32_t width) {
    for(uint32_t i=0;i<count;++i) {
        uint8_t *p=h2_ptr(m,in+i*width,width);
        copy(m,out+i*width,in+i*width,width);
        if(!p[0] && (width==1 || !p[1])) break;
    }
}
void h2_network_session_build_parameters_snapshot(h2_memory *m,uint32_t session,uint32_t c,uint32_t b,uint32_t out) {
    memset(h2_ptr(m,out,0x14d8),0,0x14d8);
    copy(m,out,session+0x1c,8);copy(m,out+8,c,4);
    h2_write32(m,out+12,b ? h2_read32(m,b) : UINT32_MAX);
    if(changed(m,c,b,4,8)) {
        flag(m,out,0x10);copy(m,out+0x14,c+8,4);copy(m,out+0x18,c+4,4);copy(m,out+0x11,session+0x765c,1);
    }
    /* Simple scalar or contiguous pair groups, in original evaluation order. */
    const uint32_t groups[][4]={{0x10,4,0x1c,0x20},{0x14,4,0x24,0x28},{0x18,8,0x2c,0x30}};
    for(uint32_t i=0;i<3;++i) if(changed(m,c,b,groups[i][0],groups[i][1])) {
        flag(m,out,groups[i][2]);copy(m,out+groups[i][3],c+groups[i][0],groups[i][1]);
    }
    if(changed(m,c,b,0x20,9)) {
        flag(m,out,0x38);copy(m,out+0x39,c+0x20,1);
        if(*h2_ptr(m,c+0x20,1)) copy(m,out+0x3a,c+0x21,8);
    }
    const uint32_t scalars[][4]={{0x2c,4,0x42,0x44},{0x4c,1,0x48,0x49},{0x50,4,0x4a,0x4c},{0x84,1,0x50,0x51},{0x80,4,0x70,0x74}};
    for(uint32_t i=0;i<5;++i) if(changed(m,c,b,scalars[i][0],scalars[i][1])) {
        flag(m,out,scalars[i][2]);copy(m,out+scalars[i][3],c+scalars[i][0],scalars[i][1]);
    }
    if(changed(m,c,b,0x54,28)) {
        flag(m,out,0x52);uint32_t kind=h2_read32(m,c+0x54);h2_write32(m,out+0x54,kind);
        if(kind==1) copy(m,out+0x58,c+0x58,16);
        else if(kind==2) copy(m,out+0x68,c+0x68,4);
        else if(kind==3) copy(m,out+0x6c,c+0x6c,4);
    }
    if(changed(m,c,b,0x85,1) || changed(m,c,b,0x88,0x308)) {
        flag(m,out,0x88);copy(m,out+0x89,c+0x85,1);copy(m,out+0x8c,c+0x88,0x308);
    }
    if(changed(m,c,b,0x70,1) || changed(m,c,b,0x78,8)) {
        flag(m,out,0x78);copy(m,out+0x79,c+0x70,1);copy(m,out+0x80,c+0x78,8);
    }
    if(changed(m,c,b,0x390,8) || text_changed(m,c+0x398,b+0x398,128,1)) {
        flag(m,out,0x394);copy(m,out+0x398,c+0x390,8);text_copy(m,out+0x3a0,c+0x398,128,1);*h2_ptr(m,out+0x41f,1)=0;
    }
    const uint32_t blocks[][4]={{0x428,8,0x420,0x428},{0x430,4,0x430,0x434},{0x434,4,0x438,0x43c},{0x438,0x130,0x440,0x444}};
    for(uint32_t i=0;i<4;++i) if(changed(m,c,b,blocks[i][0],blocks[i][1])) {
        flag(m,out,blocks[i][2]);copy(m,out+blocks[i][3],c+blocks[i][0],blocks[i][1]);
    }
    if(!b || text_changed(m,c+0x568,b+0x568,32,2)) {
        flag(m,out,0x574);text_copy(m,out+0x576,c+0x568,31,2);
    }
    if(changed(m,c,b,0x5a8,1) || changed(m,c,b,0x5ac,0xeac)) {
        flag(m,out,0x5b6);copy(m,out+0x5b7,c+0x5a8,1);copy(m,out+0x5b8,c+0x5ac,0xeac);
    }
    if(changed(m,c,b,0x29,1)) {flag(m,out,0x1464);copy(m,out+0x1465,c+0x29,1);}
    if(changed(m,c,b,0x1458,2)) {flag(m,out,0x1466);copy(m,out+0x1468,c+0x1458,2);}
    if(changed(m,c,b,0x30,1) || changed(m,c,b,0x34,24)) {
        flag(m,out,0x146a);copy(m,out+0x146b,c+0x30,1);copy(m,out+0x146c,c+0x34,24);
    }
    if(changed(m,c,b,0x1460,1) || changed(m,c,b,0x1464,68)) {
        flag(m,out,0x1484);copy(m,out+0x1485,c+0x1460,1);copy(m,out+0x1488,c+0x1464,68);
    }
    if(changed(m,c,b,0x14a8,4)) {flag(m,out,0x14cc);copy(m,out+0x14d0,c+0x14a8,4);}
}
