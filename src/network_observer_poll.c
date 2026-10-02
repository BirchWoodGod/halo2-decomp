#include "halo2/network_observer_poll.h"
#include "internal/memory.h"

static int64_t signed32(uint32_t x) {
    return x & 0x80000000u ? (int64_t)x - INT64_C(0x100000000) : x;
}

uint8_t h2_network_observer_poll_consumers(h2_memory *m,
    const h2_network_state_operations *clock, const h2_observer_consumer_query *ops,
    uint32_t observer, uint32_t index) {
    uint32_t entry = observer + 0xa8 + index * 0x528u;
    uint32_t identifier = h2_read32(m, entry + 12);
    if (identifier == UINT32_MAX) return 0;
    uint32_t connection = h2_read32(m, 0x4d87d4) + identifier * 0xf8u;
    if (signed32(h2_read32(m, connection + 0x54)) < 4) return 0;
    uint32_t previous = h2_read32(m, connection + 0xa8);
    uint32_t now = *h2_ptr(m, 0x510548, 1) ? h2_read32(m, 0x51054c) :
                   clock->ticks(clock->context);
    uint32_t config = h2_read32(m, observer + 16);
    if (signed32(now - previous) < signed32(h2_read32(m, config + 0x70))) return 0;
    for (uint32_t i = 0; i < 4; ++i) {
        if (!(*h2_ptr(m, entry + 9, 1) & (1u << i))) continue;
        uint32_t object = h2_read32(m, observer + 0x14 + i * 36u);
        uint32_t function = h2_read32(m, h2_read32(m, object));
        if (ops->query(ops->context, function, object, index)) return 1;
    }
    return 0;
}
