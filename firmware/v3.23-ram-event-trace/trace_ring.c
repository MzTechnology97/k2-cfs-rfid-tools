#include "trace_ring.h"
void cfs_trace_init(cfs_trace_ring_t *ring, uint32_t generation) {
 if (!ring) return;
 ring->header.magic=0;
 ring->header.generation=generation;
 ring->header.head=0;
 ring->header.count=0;
 ring->header.overwritten=0;
 ring->header.frozen=0;
 ring->header.last_tick=0;
 ring->header.reserved0=0;
 ring->header.reserved1=0;
 ring->header.reserved2=0;
 for (unsigned i=0; i<CFS_TRACE_CAPACITY; ++i) {
  cfs_trace_event_t *e=&ring->entries[i];
  e->tick=0; e->sequence=0; e->event=0; e->flags=0;
  e->motor0=0; e->motor1=0; e->task0=0; e->task1=0;
 }
 ring->header.magic=CFS_TRACE_MAGIC;
}
int cfs_trace_push(cfs_trace_ring_t *ring, const cfs_trace_event_t *event) {
 if (!ring || !event || ring->header.magic!=CFS_TRACE_MAGIC
     || ring->header.frozen || ring->header.head>=CFS_TRACE_CAPACITY
     || ring->header.count>CFS_TRACE_CAPACITY) return 0;
 unsigned head=ring->header.head;
 cfs_trace_event_t *dst=&ring->entries[head];
 *dst=*event;
 ring->header.last_tick=event->tick;
 ring->header.head=(uint16_t)((head+1)%CFS_TRACE_CAPACITY);
 if (ring->header.count<CFS_TRACE_CAPACITY) ring->header.count++;
 else if (ring->header.overwritten<UINT16_MAX) ring->header.overwritten++;
 return 1;
}
void cfs_trace_freeze(cfs_trace_ring_t *ring) {
 if (ring && ring->header.magic==CFS_TRACE_MAGIC)
     ring->header.frozen=1;
}
int cfs_trace_get_frozen(const cfs_trace_ring_t *ring, uint16_t i,
                         cfs_trace_event_t *out) {
 if (!ring || !out || ring->header.magic!=CFS_TRACE_MAGIC
     || !ring->header.frozen || ring->header.head>=CFS_TRACE_CAPACITY
     || ring->header.count>CFS_TRACE_CAPACITY || i>=ring->header.count)
   return 0;
 unsigned oldest=(ring->header.head+CFS_TRACE_CAPACITY-ring->header.count)
                 %CFS_TRACE_CAPACITY;
 *out=ring->entries[(oldest+i)%CFS_TRACE_CAPACITY];
 return 1;
}
