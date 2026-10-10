/* Synthetic isolated SRAM logger; no peripheral or ROM firmware writes. */
#include "trace_ring.h"
void cfs_trace_log(uint32_t pwm) {
  cfs_trace_ring_t *const ring=(cfs_trace_ring_t*)0x20006F28u;
  cfs_trace_event_t event={0};
  event.tick=ring->header.last_tick+1u;
  event.sequence=ring->header.count;
  event.event=CFS_EVENT_PWM_REQUEST;
  event.motor0=(uint16_t)pwm;
  event.motor1=0x1234u;
  event.task0=0x5678u;
  event.task1=0x9ABCu;
  (void)cfs_trace_push(ring,&event);
}