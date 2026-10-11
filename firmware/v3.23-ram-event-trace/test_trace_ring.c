#include "trace_ring.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void) {
 struct guarded { uint8_t left[32]; cfs_trace_ring_t ring; uint8_t right[32]; } g;
 memset(&g,0xAC,sizeof(g)); cfs_trace_init(&g.ring,1234);
 assert(g.ring.header.magic==CFS_TRACE_MAGIC);
 assert(g.ring.header.count==0 && g.ring.header.head==0);
 cfs_trace_event_t out={0};
 assert(!cfs_trace_get_frozen(&g.ring,0,&out));
 for (unsigned i=0;i<85;i++) {
   cfs_trace_event_t e={.tick=i*7,.sequence=(uint16_t)i,
        .event=(uint8_t)(i%7),.flags=0xA5,
        .motor0=0x100+i,.motor1=0x200+i,
        .task0=0x300+i,.task1=0x400+i};
   assert(cfs_trace_push(&g.ring,&e));
 }
 assert(g.ring.header.count==30);
 assert(g.ring.header.head==85%30);
 assert(g.ring.header.overwritten==55);
 assert(g.ring.header.last_tick==84*7);
 assert(!cfs_trace_get_frozen(&g.ring,0,&out));
 cfs_trace_freeze(&g.ring);
 assert(g.ring.header.frozen==1);
 for(unsigned i=0;i<30;i++){
   assert(cfs_trace_get_frozen(&g.ring,i,&out));
   assert(out.sequence==55+i);
   assert(out.tick==(55+i)*7);
   assert(out.motor0==(0x100+55+i));
   assert(out.task1==(0x400+55+i));
 }
 assert(!cfs_trace_get_frozen(&g.ring,30,&out));
 assert(!cfs_trace_push(&g.ring,&out));
 for(unsigned j=0;j<32;j++){
   assert(g.left[j]==0xAC && g.right[j]==0xAC);
 }
 cfs_trace_init(&g.ring,1235);
 assert(g.ring.header.generation==1235 && g.ring.header.count==0);
 assert(g.ring.header.overwritten==0);
 for(unsigned i=0;i<30;i++) {
   cfs_trace_event_t e={.tick=i};
   assert(cfs_trace_push(&g.ring,&e));
 }
 assert(g.ring.header.overwritten==0);
 cfs_trace_event_t e={.tick=31};
 assert(cfs_trace_push(&g.ring,&e));
 assert(g.ring.header.overwritten==1);
 cfs_trace_freeze(&g.ring);
 assert(cfs_trace_get_frozen(&g.ring,0,&out) && out.tick==1);
 assert(cfs_trace_get_frozen(&g.ring,29,&out) && out.tick==31);
 printf("PASS 512-byte bounded in-RAM trace, wraps, chronology, freeze, guard canaries, re-init, no out-of-bounds\n");
 return 0;
}
