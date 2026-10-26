#ifndef CFS_V323_TRACE_READBACK_H
#define CFS_V323_TRACE_READBACK_H

#include "trace_ring.h"
#include <stdint.h>
#include <stddef.h>

/* PROTOCOL MODEL ONLY, no connection to the active CFS firmware.
 * Proposed new READ-ONLY 0x57/0x15 request, one uint8 selector.
 * selector=0xFF: returns 20-byte frozen header.
 * selector=0..29: returns 16-byte event in chronological order.
 * The firmware's own motion-completion hook MUST freeze before readout;
 * calling this helper does not change the ring.
 *
 * Returns byte count (20 or 16), or zero on unsupported/incomplete/short
 * buffer. The caller must produce a protocol error for zero length.
 * Existing v3.22 API2 parameter GET/SET/RESET behavior is unchanged.
 */
enum { CFS_TRACE_SELECTOR_HEADER = 0xFF, CFS_TRACE_HEADER_WIRE_BYTES = 20 };
int cfs_trace_export_readonly(const cfs_trace_ring_t *ring,
                              uint8_t selector,
                              uint8_t *dest, size_t dest_capacity);

#endif