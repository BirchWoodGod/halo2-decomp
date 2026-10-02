#include "halo2/network_options.h"
#include "internal/memory.h"
uint32_t h2_network_option_code(uint32_t option) {
    static const uint32_t codes[]={4,0x80,0x20,0x1001,0x1002,0x4001};
    uint32_t low=option&0xffff;
    return low<6 ? codes[low] : UINT32_MAX;
}
uint32_t h2_network_socket_get_option(h2_memory *m,const h2_socket_option_platform *ops,uint32_t socket,uint32_t option) {
    if (!*h2_ptr(m,0x4d8b18,1) || !*h2_ptr(m,0x4d8b19,1)) return 0;
    uint32_t handle=h2_read32(m,socket),code=h2_network_option_code(option);
    if (handle==UINT32_MAX || code==UINT32_MAX) return 0;
    uint32_t value=0,length=4;
    if (ops->get(ops->context,handle,0xffff,code,&value,&length)) ops->last_error(ops->context);
    return value;
}
uint8_t h2_network_socket_set_option(h2_memory *m,const h2_socket_option_platform *ops,uint32_t socket,uint32_t option,uint32_t value) {
    if (!*h2_ptr(m,0x4d8b18,1) || !*h2_ptr(m,0x4d8b19,1)) return 0;
    uint32_t handle=h2_read32(m,socket),code=h2_network_option_code(option);
    if (handle==UINT32_MAX || code==UINT32_MAX) return 0;
    uint8_t bytes[4]={(uint8_t)value,(uint8_t)(value>>8),(uint8_t)(value>>16),(uint8_t)(value>>24)};
    const uint8_t *data=(option&0xffff)==5 ? h2_ptr(m,value,4) : bytes;
    if (ops->set(ops->context,handle,0xffff,code,data,4)) {
        ops->last_error(ops->context);return 0;
    }
    return 1;
}
