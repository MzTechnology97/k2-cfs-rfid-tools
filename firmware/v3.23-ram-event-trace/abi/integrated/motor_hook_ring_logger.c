/* Synthetic isolated SRAM logger; no peripheral or ROM firmware writes. */
#include "trace_ring.h"
void cfs_trace_log(uint32_t pwm) {
  cfs_trace_ring_t *const ring=(cfs_trace_ring_t*)0x20006F28u;
  cfs_trace_event_t event={0};
  event.tick=ring->header.last_tick+1u;
  /* Derive the sequence from the most recent entry, not count.
   * count is capped at 30; using it would repeat 30 on every overwrite.
   * The ring permits 16-bit wrap, with decoder modulo validation.
   * Avoid indexing memory if the single-writer ring header is invalid.
   */
  if (ring->header.magic != CFS_TRACE_MAGIC ||
      ring->header.head >= CFS_TRACE_CAPACITY ||
      ring->header.count > CFS_TRACE_CAPACITY ||
      ring->header.frozen) return;
  if (ring->header.count) {
    unsigned last = ring->header.head
        ? (unsigned)ring->header.head - 1u
        : CFS_TRACE_CAPACITY - 1u;
    event.sequence = (uint16_t)(ring->entries[last].sequence + 1u);
  }
  event.event=CFS_EVENT_PWM_REQUEST;
  event.motor0=(uint16_t)pwm;
  event.motor1=0x1234u;
  event.task0=0x5678u;
  event.task1=0x9ABCu;
  (void)cfs_trace_push(ring,&event);
}