#include "halo2/network_packet.h"
#include "internal/memory.h"
#include <string.h>

static void account_packet(h2_memory *m, const h2_network_state_operations *clock,
    uint32_t statistics, uint32_t amount) {
    h2_network_statistics_advance(m,clock,statistics);
    uint64_t packets = ((uint64_t)h2_read32(m,statistics+4)<<32) | h2_read32(m,statistics);
    uint64_t bytes = ((uint64_t)h2_read32(m,statistics+12)<<32) | h2_read32(m,statistics+8);
    uint64_t delta = amount & 0x80000000u ? UINT64_C(0xffffffff00000000) | amount : amount;
    ++packets; bytes += delta;
    h2_write32(m,statistics,(uint32_t)packets);h2_write32(m,statistics+4,(uint32_t)(packets>>32));
    h2_write32(m,statistics+8,(uint32_t)bytes);h2_write32(m,statistics+12,(uint32_t)(bytes>>32));
    h2_write32(m,statistics+0x14,h2_read32(m,statistics+0x14)+1);
    h2_write32(m,statistics+0x18,h2_read32(m,statistics+0x18)+amount);
}
void h2_network_packet_submit(h2_memory *m, const h2_network_state_operations *clock,
    const h2_socket_send_platform *send, uint32_t packet, uint32_t endpoint,
    uint32_t scratch, uint8_t address_workspace[28]) {
    h2_network_packet_pack(m,packet,scratch+4,scratch);
    const uint8_t *width=h2_ptr(m,packet+0x1a,2);
    if (!(width[0]==4 && width[1]==0 && h2_read32(m,packet+8)==0x7f000001)) {
        uint32_t amount=h2_read32(m,packet+0x1c);
        account_packet(m,clock,endpoint+0x228,amount);
        amount=h2_network_packet_accounted_size(m,packet);
        account_packet(m,clock,endpoint+0x3d8,amount);
    }
    uint32_t size=h2_read32(m,scratch);
    if (size && size<=0x518)
        h2_network_endpoint_send(m,send,endpoint,h2_read32(m,packet),packet+8,size,scratch+4,address_workspace);
}

static void copy_forward(h2_memory *m, uint32_t dst, uint32_t src, uint32_t size) {
    uint32_t words = size >> 2;
    for (uint32_t i = 0; i < words; ++i) h2_write32(m, dst+i*4, h2_read32(m, src+i*4));
    for (uint32_t i = words*4; i < size; ++i) *h2_ptr(m, dst+i, 1) = *h2_ptr(m, src+i, 1);
}
void h2_network_packet_send_datagram(h2_memory *m, const h2_network_state_operations *clock,
    const h2_socket_send_platform *send, uint32_t stream, uint32_t address, uint32_t endpoint,
    uint32_t size_output, uint32_t scratch, uint8_t address_workspace[28]) {
    memset(h2_ptr(m,scratch,0x824),0,0x824);
    copy_forward(m,scratch+8,address,20);
    uint32_t size=h2_read32(m,stream+4), accounted=0;
    h2_write32(m,scratch,3);h2_write32(m,scratch+0x1c,size);
    if (size<=0x600) {
        copy_forward(m,scratch+0x20,h2_read32(m,stream),size);
        h2_network_packet_submit(m,clock,send,scratch,endpoint,scratch+0x824,address_workspace);
        accounted=h2_network_packet_accounted_size(m,scratch);
    }
    if (size_output) h2_write32(m,size_output,accounted);
}
void h2_network_packet_pack(h2_memory *m, uint32_t packet, uint32_t destination, uint32_t size_output) {
    if (h2_read32(m, packet) == 3) {
        copy_forward(m, destination, packet+0x20, h2_read32(m, packet+0x1c));
        h2_write32(m, size_output, h2_read32(m, packet+0x1c));
    } else {
        uint32_t size = h2_read32(m, packet+0x1c);
        uint8_t *prefix = h2_ptr(m, destination, 2);
        prefix[0] = (uint8_t)size; prefix[1] = (uint8_t)(size >> 8);
        copy_forward(m, destination+2, packet+0x20, h2_read32(m, packet+0x1c));
        copy_forward(m, destination+2+h2_read32(m, packet+0x1c), packet+0x624, h2_read32(m, packet+0x620));
        h2_write32(m, size_output, h2_read32(m, packet+0x1c)+h2_read32(m, packet+0x620)+2);
    }
}
uint8_t h2_network_packet_unpack(h2_memory *m, uint32_t packet, uint32_t size, uint32_t source) {
    if (h2_read32(m, packet) == 3) {
        if (size > 0x600) return 0;
        h2_write32(m, packet+0x1c, size);
        copy_forward(m, packet+0x20, source, size);
    } else {
        if (size < 2 || (size & 0x80000000u)) return 0;
        const uint8_t *prefix = h2_ptr(m, source, 2);
        uint32_t primary = prefix[0] | (uint32_t)prefix[1] << 8;
        h2_write32(m, packet+0x1c, primary);
        uint32_t secondary = size-primary-2;
        h2_write32(m, packet+0x620, secondary);
        if (primary > 0x600 || secondary > 0x200) return 0;
        copy_forward(m, packet+0x20, source+2, primary);
        copy_forward(m, packet+0x624, source+2+h2_read32(m, packet+0x1c), h2_read32(m, packet+0x620));
    }
    return 1;
}
uint32_t h2_network_packet_accounted_size(h2_memory *m, uint32_t packet) {
    uint32_t size = h2_read32(m, packet+0x1c);
    if (!(size & 0x80000000u) && (size & 7)) size += 8-(size & 7);
    return size+h2_read32(m, packet+0x620)+(h2_read32(m, packet) == 3 ? 44 : 45);
}
