#include "halo2/network_identity_resolve.h"
#include "halo2/network_address.h"
#include "internal/memory.h"
uint8_t h2_network_identity_resolve(h2_memory *m,const h2_identity_resolve_platform *ops,
    uint32_t address,uint32_t direct,uint32_t index4,uint32_t key8,uint32_t metadata16,uint32_t identity36) {
    uint32_t s=ops->scratch32,last=0;uint8_t success=0;
    h2_write32(m,s,UINT32_MAX);
    for(uint32_t i=8;i<28;i+=4) h2_write32(m,s+i,0);
    const uint8_t *p=h2_ptr(m,address+18,2);
    if(p[0]==4 && !p[1]) {
        uint32_t ip=h2_read32(m,address);
        if(ip) {
            if(direct) {
                uint32_t reversed=(ip>>24)|((ip>>8)&0xff00u)|((ip<<8)&0xff0000u)|(ip<<24);
                for(uint32_t i=0;i<36;i+=4) h2_write32(m,identity36+i,0);
                h2_write32(m,identity36,reversed);success=1;
            } else if(h2_network_address_registered_ipv4(m,address,s+4) &&
                      !ops->resolve(ops->context,h2_read32(m,s+4),identity36,s+8)) {
                success=1;
                for(uint32_t i=0;i<8;++i) {
                    uint32_t entry=0x4cf7d4+i*32;
                    if(!*h2_ptr(m,entry,1) || h2_read32(m,entry+8)!=h2_read32(m,s+8) ||
                       h2_read32(m,entry+12)!=h2_read32(m,s+12)) continue;
                    h2_write32(m,s,i);
                    for(uint32_t j=0;j<12;j+=4) h2_write32(m,s+16+j,h2_read32(m,entry+16+j));
                    last=h2_read32(m,entry+28);break;
                }
            }
        }
    }
    if(index4) h2_write32(m,index4,h2_read32(m,s));
    if(key8) {
        uint32_t a=h2_read32(m,s+8),b=h2_read32(m,s+12);
        h2_write32(m,key8,a);h2_write32(m,key8+4,b);
    }
    if(metadata16) {
        uint32_t a=h2_read32(m,s+16),b=h2_read32(m,s+20),c=h2_read32(m,s+24);
        h2_write32(m,metadata16,a);h2_write32(m,metadata16+4,b);h2_write32(m,metadata16+8,c);h2_write32(m,metadata16+12,last);
    }
    return success;
}
