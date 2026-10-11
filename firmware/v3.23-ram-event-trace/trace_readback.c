#include "trace_readback.h"

/* Explicit little-endian byte serialization: neither ABI padding nor
 * host-endian struct layout is exposed over the existing framed UART.
 * This function never writes to the source ring or any motor register.
 */
static void u16le(uint8_t *p, uint16_t v) {
    p[0]=(uint8_t)v;
    p[1]=(uint8_t)(v>>8);
}
static void u32le(uint8_t *p, uint32_t v) {
    u16le(p,(uint16_t)v);
    u16le(p+2,(uint16_t)(v>>16));
}
int cfs_trace_export_readonly(const cfs_trace_ring_t *ring,
                              uint8_t selector, uint8_t *dest,
                              size_t capacity) {
    if (!ring || !dest ||
        ring->header.magic!=CFS_TRACE_MAGIC ||
        ring->header.frozen!=1 ||
        ring->header.head>=CFS_TRACE_CAPACITY ||
        ring->header.count>CFS_TRACE_CAPACITY ||
        (ring->header.count<CFS_TRACE_CAPACITY &&
          (ring->header.head!=ring->header.count ||
           ring->header.overwritten!=0)) ||
        (ring->header.count==CFS_TRACE_CAPACITY &&
          ring->header.overwritten!=UINT16_MAX &&
          ring->header.head!=(ring->header.overwritten%CFS_TRACE_CAPACITY)))
        return 0;

    if (selector==CFS_TRACE_SELECTOR_HEADER) {
        if (capacity<CFS_TRACE_HEADER_WIRE_BYTES) return 0;
        u32le(dest,   ring->header.magic);
        u32le(dest+4, ring->header.generation);
        u16le(dest+8, ring->header.head);
        u16le(dest+10,ring->header.count);
        u16le(dest+12,ring->header.overwritten);
        u16le(dest+14,ring->header.frozen);
        u32le(dest+16,ring->header.last_tick);
        return CFS_TRACE_HEADER_WIRE_BYTES;
    }

    cfs_trace_event_t e;
    if (selector>=CFS_TRACE_CAPACITY ||
        !cfs_trace_get_frozen(ring,selector,&e) ||
        capacity<sizeof(e)) return 0;
    u32le(dest,   e.tick);
    u16le(dest+4, e.sequence);
    dest[6]=e.event;
    dest[7]=e.flags;
    u16le(dest+8, e.motor0);
    u16le(dest+10,e.motor1);
    u16le(dest+12,e.task0);
    u16le(dest+14,e.task1);
    return (int)sizeof(e);
}