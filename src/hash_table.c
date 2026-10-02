#include "halo2/hash_table.h"
#include "internal/memory.h"
#include <string.h>

void h2_hash_clear(h2_memory *m,uint32_t table) {
    uint32_t buckets=h2_read32(m,table+0x20),capacity=h2_read32(m,table+0x24);
    uint32_t stride=h2_read32(m,table+0x28)+12;
    memset(h2_ptr(m,table+0x3c,buckets*4+capacity*stride),0,buckets*4+capacity*stride);
    h2_write32(m,table+0x38,0);
    uint32_t node=table+0x3c+buckets*4;
    for (uint32_t i=0;i<capacity;i++,node+=stride) {
        h2_write32(m,node+8,h2_read32(m,table+0x38));
        h2_write32(m,table+0x38,node);
    }
}
uint32_t h2_hash_create(h2_memory *m,const h2_allocator *ops,uint32_t allocator,uint32_t name,
    uint32_t capacity,uint32_t payload_size,uint32_t buckets,uint32_t hash,uint32_t equal) {
    uint32_t table=ops->allocate(ops->context,allocator,(payload_size+12)*capacity+0x3c+buckets*4);
    if (!table) return 0;
    uint8_t ch=1;
    for (uint32_t i=0;i<32;i++) {
        if (ch) ch=*h2_ptr(m,name+i,1);
        *h2_ptr(m,table+i,1)=ch;
    }
    *h2_ptr(m,table+0x1f,1)=0;
    h2_write32(m,table+0x20,buckets);h2_write32(m,table+0x24,capacity);
    h2_write32(m,table+0x28,payload_size);h2_write32(m,table+0x2c,hash);
    h2_write32(m,table+0x30,equal);h2_write32(m,table+0x34,allocator);
    h2_hash_clear(m,table);
    return table;
}
uint8_t h2_hash_insert(h2_memory *m,const h2_key_ops *ops,uint32_t table,uint32_t key,uint32_t payload) {
    if (!h2_read32(m,table+0x38)) return 0;
    uint32_t hash=ops->hash(ops->context,h2_read32(m,table+0x2c),key);
    uint32_t bucket=hash%h2_read32(m,table+0x20);
    uint32_t node=h2_read32(m,table+0x38);
    h2_write32(m,table+0x38,h2_read32(m,node+8));
    h2_write32(m,node+4,hash);h2_write32(m,node,key);
    uint32_t size=h2_read32(m,table+0x28),i=0;
    /* Preserve REP MOVSD/MOVSB order, without host unaligned accesses. */
    for (;i+4<=size;i+=4) h2_write32(m,node+12+i,h2_read32(m,payload+i));
    for (;i<size;i++) *h2_ptr(m,node+12+i,1)=*h2_ptr(m,payload+i,1);
    h2_write32(m,node+8,h2_read32(m,table+0x3c+bucket*4));
    h2_write32(m,table+0x3c+bucket*4,node);
    return 1;
}
uint32_t h2_hash_find(h2_memory *m,const h2_key_ops *ops,uint32_t table,uint32_t key) {
    uint32_t hash=ops->hash(ops->context,h2_read32(m,table+0x2c),key);
    uint32_t bucket=hash%h2_read32(m,table+0x20);
    for (uint32_t node=h2_read32(m,table+0x3c+bucket*4);node;node=h2_read32(m,node+8))
        if (hash==h2_read32(m,node+4) && ops->equal(ops->context,h2_read32(m,table+0x30),key,h2_read32(m,node))) return node;
    return 0;
}
uint8_t h2_hash_remove(h2_memory *m,const h2_key_ops *ops,uint32_t table,uint32_t key) {
    uint32_t hash=ops->hash(ops->context,h2_read32(m,table+0x2c),key);
    uint32_t link=table+0x3c+(hash%h2_read32(m,table+0x20))*4;
    for (uint32_t node=h2_read32(m,link);node;node=h2_read32(m,link)) {
        if (ops->equal(ops->context,h2_read32(m,table+0x30),key,h2_read32(m,node))) {
            h2_write32(m,link,h2_read32(m,node+8));
            h2_write32(m,node+8,h2_read32(m,table+0x38));
            h2_write32(m,table+0x38,node);
            return 1;
        }
        link=node+8;
    }
    return 0;
}
uint32_t h2_actor_owner_hash(uint32_t key) { return (key&255)*4; }
uint8_t h2_actor_owner_equal(uint32_t left,uint32_t right) { return left==right; }
static uint32_t actor_hash(void *context,uint32_t function,uint32_t key) {
    (void)context;if (function!=0x25dd20) abort();return h2_actor_owner_hash(key);
}
static int actor_equal(void *context,uint32_t function,uint32_t left,uint32_t right) {
    (void)context;if (function!=0x25dd30) abort();return h2_actor_owner_equal(left,right);
}
h2_key_ops h2_actor_owner_key_ops(void) { return (h2_key_ops){NULL,actor_hash,actor_equal}; }
