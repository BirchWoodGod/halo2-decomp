#include "halo2/engine_pools.h"
#include "halo2/data_array.h"
#include "halo2/crc.h"
#include "halo2/hash_table.h"
#include "internal/memory.h"

void h2_command_scripts_initialize(h2_memory *m, const h2_allocator *ops) {
    uint32_t allocator = h2_read32(m, 0x510c2c);
    uint32_t scripts = h2_data_create(m, ops, allocator, 0x45a690, 40, 0xd4, 0);
    allocator = h2_read32(m, 0x510c2c);
    h2_write32(m, 0x502408, scripts);
    uint32_t joint_scripts = h2_data_create(m, ops, allocator, 0x45a678, 10, 0x8c, 0);
    h2_write32(m, 0x502404, joint_scripts);
}
void h2_havok_components_initialize(h2_memory *m, const h2_allocator *ops) {
    uint32_t allocator = h2_read32(m, 0x468758);
    uint32_t components = h2_data_create(m, ops, allocator, 0x455abc, 512, 0xa0, 4);
    h2_write32(m, 0x51e9b8, components);
}
void h2_actors_initialize(h2_memory *m,const h2_allocator *ops) {
    uint32_t allocator=h2_read32(m,0x510c2c);
    uint32_t actors=h2_data_create(m,ops,allocator,0x455ba8,256,0x888,0);
    uint32_t offset=h2_read32(m,0x4e6084),arena=h2_read32(m,0x4e6080);
    h2_write32(m,0x4f55f0,actors);
    h2_write32(m,0x4e6084,offset+0x640);
    const uint8_t reservation_size[4]={0x40,0x06,0x00,0x00};
    h2_crc_update_bytes(m,0x4e608c,reservation_size,4);
    allocator=h2_read32(m,0x510c2c);
    h2_write32(m,0x4f93a0,arena+offset);
    uint32_t owners=h2_hash_create(m,ops,allocator,0x455b88,256,4,1024,0x25dd20,0x25dd30);
    h2_write32(m,0x557c6c,owners);
}
