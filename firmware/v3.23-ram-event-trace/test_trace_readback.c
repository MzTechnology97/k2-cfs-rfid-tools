#include "trace_readback.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned u16(const uint8_t *p) {
    return (unsigned)p[0]|((unsigned)p[1]<<8);
}
static uint32_t u32(const uint8_t *p) {
    return (uint32_t)u16(p)|((uint32_t)u16(p+2)<<16);
}

int main(void) {
    struct guarded {
        uint8_t before[16];
        cfs_trace_ring_t ring;
        uint8_t after[16];
    } data;
    uint8_t dest[48];
    memset(&data,0xB7,sizeof(data));
    memset(dest,0xCA,sizeof(dest));
    cfs_trace_init(&data.ring,0x12345678u);
    cfs_trace_ring_t saved;

    /* A GET-like reader must never mutate the ring or reveal an unfrozen
       buffer even when its header magic is valid. */
    memcpy(&saved,&data.ring,sizeof(saved));
    assert(cfs_trace_export_readonly(&data.ring,0xFF,dest,sizeof(dest))==0);
    assert(memcmp(&saved,&data.ring,sizeof(saved))==0);
    assert(cfs_trace_export_readonly(&data.ring,0,dest,sizeof(dest))==0);

    for (unsigned i=0;i<43;i++) {
        cfs_trace_event_t e={.tick=1000+i*17,.sequence=(uint16_t)i,
                             .event=CFS_EVENT_PWM_REQUEST,.flags=0xA5,
                             .motor0=(uint16_t)(i*7),.motor1=0x1234,
                             .task0=0x5678,.task1=0x9ABC};
        assert(cfs_trace_push(&data.ring,&e));
    }
    cfs_trace_freeze(&data.ring);
    memcpy(&saved,&data.ring,sizeof(saved));

    assert(cfs_trace_export_readonly(&data.ring,0xFF,dest,19)==0);
    assert(cfs_trace_export_readonly(&data.ring,0xFF,dest,20)==20);
    assert(u32(dest)==CFS_TRACE_MAGIC);
    assert(u32(dest+4)==0x12345678u);
    assert(u16(dest+8)==13);
    assert(u16(dest+10)==30);
    assert(u16(dest+12)==13);
    assert(u16(dest+14)==1);
    assert(u32(dest+16)==1000+42*17);
    for (unsigned j=20;j<48;j++) assert(dest[j]==0xCA);
    assert(memcmp(&saved,&data.ring,sizeof(saved))==0);

    for (unsigned i=0;i<30;i++) {
        memset(dest,0xCA,sizeof(dest));
        assert(cfs_trace_export_readonly(&data.ring,(uint8_t)i,dest,15)==0);
        assert(cfs_trace_export_readonly(&data.ring,(uint8_t)i,dest,16)==16);
        assert(u32(dest)==1000+(13+i)*17);
        assert(u16(dest+4)==13+i);
        assert(dest[6]==CFS_EVENT_PWM_REQUEST && dest[7]==0xA5);
        assert(u16(dest+8)==(13+i)*7);
        assert(u16(dest+10)==0x1234);
        assert(u16(dest+12)==0x5678);
        assert(u16(dest+14)==0x9ABC);
        for (unsigned j=16;j<48;j++) assert(dest[j]==0xCA);
    }
    assert(cfs_trace_export_readonly(&data.ring,30,dest,sizeof(dest))==0);
    assert(cfs_trace_export_readonly(&data.ring,254,dest,sizeof(dest))==0);
    assert(cfs_trace_export_readonly(&data.ring,0xFF,NULL,sizeof(dest))==0);
    assert(cfs_trace_export_readonly(NULL,0xFF,dest,sizeof(dest))==0);
    assert(memcmp(&saved,&data.ring,sizeof(saved))==0);
    for (unsigned i=0;i<16;i++)
        assert(data.before[i]==0xB7 && data.after[i]==0xB7);
    /* Full-ring head must match overwrite modulo capacity until saturation. */
    data.ring.header.overwritten=0;
    assert(cfs_trace_export_readonly(&data.ring,0xFF,dest,sizeof(dest))==0);
    data.ring.header.overwritten=2;
    assert(cfs_trace_export_readonly(&data.ring,0xFF,dest,sizeof(dest))==0);
    data.ring.header.overwritten=13;
    assert(cfs_trace_export_readonly(&data.ring,0xFF,dest,sizeof(dest))==20);
    data.ring.header.head=30;
    assert(cfs_trace_export_readonly(&data.ring,0xFF,dest,sizeof(dest))==0);
    data.ring.header.count=2;
    data.ring.header.head=3;
    data.ring.header.overwritten=0;
    assert(cfs_trace_export_readonly(&data.ring,0xFF,dest,sizeof(dest))==0);
    data.ring.header.head=2;
    data.ring.header.overwritten=1;
    assert(cfs_trace_export_readonly(&data.ring,0xFF,dest,sizeof(dest))==0);
    data.ring.header.frozen=0;
    assert(cfs_trace_export_readonly(&data.ring,0,dest,sizeof(dest))==0);
    puts("PASS: read-only 20-byte header and 30 chronological 16-byte events; no source mutations/OOB");
    return 0;
}