/* Offline-only fixture producer: frozen C event ring -> wire bytes on stdout. */
#include "trace_readback.h"
#include <stdint.h>
#include <stdio.h>
int main(void) {
    cfs_trace_ring_t ring;
    uint8_t payload[32];
    cfs_trace_init(&ring, 42);
    for (unsigned i=0; i<39; i++) {
        cfs_trace_event_t event = {
            .tick=100u+i*17u, .sequence=(uint16_t)i,
            .event=CFS_EVENT_PWM_REQUEST, .flags=0xA5,
            .motor0=(uint16_t)(3u*i), .motor1=0x1234,
            .task0=0x5678, .task1=0x9ABC,
        };
        if (!cfs_trace_push(&ring, &event)) return 2;
    }
    cfs_trace_freeze(&ring);
    if (cfs_trace_export_readonly(&ring, 0xFF, payload, sizeof(payload))!=20)
        return 3;
    if (fwrite(payload,1,20,stdout)!=20) return 4;
    for (unsigned j=0; j<CFS_TRACE_CAPACITY; j++) {
        if (cfs_trace_export_readonly(&ring,(uint8_t)j,payload,sizeof(payload))!=16)
            return 5;
        if (fwrite(payload,1,16,stdout)!=16) return 6;
    }
    if (cfs_trace_export_readonly(&ring,0xFF,payload,sizeof(payload))!=20)
        return 7;
    if (fwrite(payload,1,20,stdout)!=20) return 8;
    return 0;
}
