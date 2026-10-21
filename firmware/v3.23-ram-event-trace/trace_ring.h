#ifndef CFS_V323_TRACE_RING_H
#define CFS_V323_TRACE_RING_H
#include <stdint.h>
#include <stddef.h>
/*
 * OFFLINE MODEL ONLY. A validated MCU hook, RAM reservation, clock source,
 * atomic writer ownership and safe reader handshake do not yet exist.
 * No hardware I/O, no EEPROM, no motor hooks, no permission to SET/RESET.
 */
enum {
 CFS_TRACE_MAGIC = 0x33544643u,  /* "CFT3" little endian */
 CFS_TRACE_CAPACITY = 30,
 CFS_TRACE_BYTES = 512,
 CFS_EVENT_PWM_REQUEST = 1,
 CFS_EVENT_PWM_RETURN = 2,
 CFS_EVENT_FEED_BEGIN = 3,
 CFS_EVENT_FEED_END = 4,
 CFS_EVENT_RETRACT_BEGIN = 5,
 CFS_EVENT_RETRACT_END = 6,
 CFS_EVENT_UNKNOWN = 255,
};

typedef struct {
 uint32_t tick;
 uint16_t sequence;
 uint8_t event;
 uint8_t flags;
 uint16_t motor0;
 uint16_t motor1;
 uint16_t task0;
 uint16_t task1;
} cfs_trace_event_t;

typedef struct {
 uint32_t magic;
 uint32_t generation;
 uint16_t head;          /* index of next write */
 uint16_t count;         /* number of valid records, <= 30 */
 uint16_t overwritten;   /* saturating counter */
 uint16_t frozen;        /* 0 or 1 */
 uint32_t last_tick;
 uint32_t reserved0;
 uint32_t reserved1;
 uint32_t reserved2;
} cfs_trace_header_t;

typedef struct {
 cfs_trace_header_t header;
 cfs_trace_event_t entries[CFS_TRACE_CAPACITY];
} cfs_trace_ring_t;

_Static_assert(sizeof(cfs_trace_event_t)==16, "event must be 16 bytes");
_Static_assert(sizeof(cfs_trace_header_t)==32, "header must be 32 bytes");
_Static_assert(sizeof(cfs_trace_ring_t)==CFS_TRACE_BYTES,"ring must fit 512 bytes");

/* Caller MUST ensure exclusive single-writer access, no interrupts/concurrency. */
void cfs_trace_init(cfs_trace_ring_t *ring, uint32_t generation);
int cfs_trace_push(cfs_trace_ring_t *ring, const cfs_trace_event_t *event);
/* Freeze before any concurrent reader; this model does NOT implement barriers. */
void cfs_trace_freeze(cfs_trace_ring_t *ring);
/* Read record i in chronological order, from oldest 0 to latest count-1. */
int cfs_trace_get_frozen(const cfs_trace_ring_t *ring, uint16_t i,
                         cfs_trace_event_t *out);
#endif
