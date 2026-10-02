#include "halo2/xbe_image.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t word(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static int fail(char *error,size_t size,const char *message) {
    if (size) snprintf(error,size,"%s",message);
    return 0;
}
int h2_xbe_load(h2_heap *heap,const char *path,char *error,size_t error_size) {
    static const unsigned char expected[32] = {
        0x03,0x21,0x59,0x19,0xbb,0x71,0x63,0x25,0x92,0x57,0xd3,0x61,0xf4,0xc7,0xbf,0x80,
        0x2a,0x7a,0xb1,0x2a,0xa8,0x5e,0x26,0x89,0x43,0x63,0x69,0xb5,0xc4,0x27,0x93,0x5d
    };
    h2_memory *memory = h2_heap_memory(heap);
    if (memory->base!=0x10000 || h2_heap_live_allocations(heap))
        return fail(error,error_size,"image requires an empty heap at guest base 0x10000");
    FILE *f = fopen(path,"rb");
    if (!f) return fail(error,error_size,"cannot open XBE");
    if (fseek(f,0,SEEK_END)!=0) { fclose(f); return fail(error,error_size,"cannot seek XBE"); }
    long length=ftell(f);
    if (length<0x178 || length>16*1024*1024 || fseek(f,0,SEEK_SET)!=0) {
        fclose(f);return fail(error,error_size,"invalid XBE file length");
    }
    size_t size=(size_t)length;
    unsigned char *data=malloc(size);
    if (!data) { fclose(f);return fail(error,error_size,"out of memory reading XBE"); }
    size_t got=fread(data,1,size,f);
    int read_error=ferror(f);fclose(f);
    if (got!=size || read_error) { free(data);return fail(error,error_size,"cannot read complete XBE"); }
    unsigned char digest[EVP_MAX_MD_SIZE];unsigned int digest_size=0;
    int hash_ok=EVP_Digest(data,size,digest,&digest_size,EVP_sha256(),NULL);
    if (!hash_ok || digest_size!=32 || memcmp(digest,expected,32)) {
        free(data);return fail(error,error_size,"unsupported XBE SHA-256 (expected Halo 2 retail profile)");
    }
    uint32_t base=word(data+0x104),headers=word(data+0x108),image_size=word(data+0x10c);
    uint32_t count=word(data+0x11c),table=word(data+0x120);
    if (memcmp(data,"XBEH",4) || base!=memory->base || headers>size || headers>image_size ||
        image_size>memory->size || table<base || (uint64_t)(table-base)+(uint64_t)count*0x38>size) {
        free(data);return fail(error,error_size,"invalid XBE image layout");
    }
    for (uint32_t i=0;i<count;i++) {
        const unsigned char *s=data+(table-base)+i*0x38;
        uint32_t va=word(s+4),virtual_size=word(s+8),raw=word(s+12),raw_size=word(s+16);
        if (va<base || (uint64_t)(va-base)+virtual_size>image_size || raw_size>virtual_size ||
            (uint64_t)raw+raw_size>size) {
            free(data);return fail(error,error_size,"invalid XBE section bounds");
        }
    }
    uint32_t allocation=h2_heap_allocate(heap,image_size);
    if (allocation!=base) { free(data);return fail(error,error_size,"cannot reserve image allocation"); }
    memset(memory->bytes,0,image_size);
    memcpy(memory->bytes,data,headers);
    for (uint32_t i=0;i<count;i++) {
        const unsigned char *s=data+(table-base)+i*0x38;
        memcpy(memory->bytes+word(s+4)-base,data+word(s+12),word(s+16));
    }
    free(data);
    if (error_size) error[0]=0;
    return 1;
}
