/* SGF1: RAM family geometry. The host declares family after decoding a tag.
 * This module does not identify vendors, initiate RF, or write nonvolatile data. */
#include <stdint.h>
#include <stddef.h>
#define ROWS ((volatile Slot *)0x20006F28u)
#define CATALOG ((volatile Geometry *)0x20007028u)
#define INTERNAL ((volatile uint8_t *)0x20004460u)
#define RUNTIME ((volatile uint8_t *)0x20004590u)
#define PERCENT ((volatile uint8_t *)0x20003974u)
#define MANAGER ((volatile uint8_t *)0x2000391Cu)
#define STATE ((volatile uint8_t *)0x200001F0u)
#define HW (*(volatile uint8_t *)0x20000000u)
#define BOX (*(volatile uint8_t *)0x200037D2u)
#define TICK (*(volatile uint32_t *)0x200009E4u)
typedef struct {
    uint32_t generation, uid, raw_bits, tick, flags, bound_uid, profile, revision;
    uint32_t compare_a, compare_b, compare_status, auth_uid, auth_ok, auth_fail;
    uint32_t applied_generation, epoch;
} Slot;
typedef struct { uint32_t revision; uint16_t core10, full10; uint32_t total, reserved; } Geometry;
_Static_assert(sizeof(Slot)==64 && sizeof(Geometry)==16, "reserved SRAM layout");
static inline uint32_t lock(void) {
    uint32_t m; __asm__ volatile("mrs %0, primask\n cpsid i":"=r"(m)::"memory"); return m;
}
static inline void unlock(uint32_t m) { __asm__ volatile("msr primask, %0"::"r"(m):"memory"); }
static inline uint32_t get32(const volatile uint8_t *p) {
    return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static inline uint32_t get16(const uint8_t *p) { return p[0]|((uint32_t)p[1]<<8); }
static inline void put32(volatile uint8_t *p,uint32_t v) {
    p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;
}
static inline void put16(uint8_t *p,uint32_t v) { p[0]=v;p[1]=v>>8; }
static inline volatile uint8_t *runtime(unsigned s) { return RUNTIME+s*100u; }
static uint32_t uid(unsigned s) {
    volatile uint8_t *r=INTERNAL+s*76u;
    return r[60]==4 && r[61]==0 && r[74]==8 ? get32(r+62):0;
}
static uint32_t next_epoch(uint32_t e) { return e==0xffffffffu?1:e+1; }
static void transient(volatile Slot *p) {
    p->epoch=next_epoch(p->epoch);p->compare_status=0;p->auth_uid=0;
    p->auth_ok=0;p->auth_fail=0;
}
/* These hooks use integer operations only and must preserve every VFP register. */
void sgf_begin(unsigned s) {
    if(s>=4)return;uint32_t m=lock();transient(ROWS+s);ROWS[s].flags=0;unlock(m);
}
void sgf_cancel_transients(void) {
    uint32_t m=lock();for(unsigned s=0;s<4;++s)transient(ROWS+s);unlock(m);
}
void sgf_compare(unsigned s,uint32_t result,const uint8_t *a,const uint8_t *b) {
    if(s>=4)return;uint32_t m=lock();volatile Slot *p=ROWS+s;
    p->compare_a=get32(a);p->compare_b=get32(b);p->compare_status=result?2:1;unlock(m);
}
void sgf_invalidate_compare(unsigned s) {
    if(s>=4)return;uint32_t m=lock();ROWS[s].compare_status=0;unlock(m);
}
static int record_slot(const volatile uint8_t *r) {
    uintptr_t delta=(uintptr_t)r-(uintptr_t)INTERNAL;
    if(delta>=304 || delta%76)return -1;return delta/76;
}
uint32_t sgf_auth_epoch(const volatile uint8_t *r,const uint8_t *tag_uid) {
    int s=record_slot(r);if(s<0 || uid(s)!=get32(tag_uid))return 0;return ROWS[s].epoch;
}
void sgf_auth_result(const volatile uint8_t *r,unsigned index_success,
                     const uint8_t *tag_uid,uint32_t epoch) {
    int s=record_slot(r);unsigned i=index_success&255u;
    if(s<0 || i>=3 || !epoch)return;
    uint32_t m=lock();volatile Slot *p=ROWS+s;uint32_t u=get32(tag_uid);
    if(p->epoch==epoch && u && uid(s)==u) {
        if(p->auth_uid && p->auth_uid!=u)p->auth_ok=p->auth_fail=0;
        p->auth_uid=u;
        if(index_success&256u)p->auth_ok|=1u<<i;else p->auth_fail|=1u<<i;
    }
    unlock(m);
}
static int complete(unsigned s,volatile Slot *p) {
    volatile uint8_t *r=INTERNAL+s*76u;
    volatile uint8_t *a=INTERNAL+((s+2u)&3u)*76u;
    volatile uint8_t *b=INTERNAL+((s+3u)&3u)*76u;
    return p->auth_uid==p->uid && p->auth_ok==7 && !p->auth_fail &&
           r[9]==7 && r[10]==7 && !r[11] &&
           get32(a+4)==0x3343324bu && get32(b+4)==0x3344324bu &&
           get32(r+12)==0x4c52324bu;
}
void sgf_capture(uint32_t bits,unsigned s,unsigned result,unsigned native_valid) {
    (void)native_valid; /* R9 is also set by the API7 success override. */
    if(s>=4)return;uint32_t m=lock();volatile Slot *p=ROWS+s;uint32_t u=uid(s);
    if(p->bound_uid!=u){p->bound_uid=0;p->profile=0;p->revision=0;p->applied_generation=0;}
    p->generation=next_epoch(p->generation);p->uid=u;p->raw_bits=bits;p->tick=TICK;
    int same=p->compare_status==1 && u && p->compare_a==u && p->compare_b==u;
    uint32_t flags=(same?16u:0u)|(p->compare_status==2?4u:0u)|(result?8u:0u);
    if(!result && !HW && u && bits>=0x42480000u && bits<=0x44fa0000u && same)flags|=1;
    if(u && complete(s,p))flags|=2;
    p->flags=flags;p->compare_status=0;unlock(m);
}
static int bound(unsigned s,volatile Slot *p) {
    return p->profile>=1 && p->profile<=4 && p->bound_uid && p->bound_uid==uid(s);
}
static int usable(unsigned s,volatile Slot *p) {
    return (p->flags&3)==3 && p->uid && p->uid==uid(s) && p->generation && !HW;
}
static int valid_runtime(volatile uint8_t *r);
int sgf_preserve_runtime(unsigned s) {
    if(s>=4 || !bound(s,ROWS+s) || !valid_runtime(runtime(s)))return 0;
    return CATALOG[ROWS[s].profile-1].revision &&
           (runtime(s)[22]!=0 || !usable(s,ROWS+s));
}
static unsigned percent(uint32_t bits,volatile Geometry *g) {
    union{uint32_t bits;float f;}raw={.bits=bits};
    float c=raw.f,core=g->core10*0.1f,full=g->full10*0.1f;
    if(c<=core)return 1;if(c>=full)return 100;
    unsigned p=(unsigned)(100.0f*(c*c-core*core)/(full*full-core*core)+0.5f);
    return p<1?1:p>100?100:p;
}
/* Called within the existing geometry atomic section. No counters reset here.
 * On an idle reread the OEM initializer is given a fresh calibrated anchor. */
unsigned sgf_geometry_percent(unsigned s,unsigned fallback) {
    if(s>=4)return fallback;
    if(sgf_preserve_runtime(s))return PERCENT[s];
    if(runtime(s)[22]!=0)return fallback;volatile Slot *p=ROWS+s;
    if(!bound(s,p) || !usable(s,p))return fallback;
    volatile Geometry *g=CATALOG+p->profile-1;if(!g->revision)return fallback;
    unsigned value=percent(p->raw_bits,g);p->revision=g->revision;
    p->applied_generation=p->generation;return value;
}
uint32_t sgf_total(unsigned s) {
    if(s>=4)return 0;volatile Slot *p=ROWS+s;
    if(!bound(s,p) || !usable(s,p) || p->applied_generation!=p->generation)return 0;
    volatile Geometry *g=CATALOG+p->profile-1;
    return g->revision && g->revision==p->revision ? g->total:0;
}
static int idle(void) {
    if(BOX || MANAGER[0]!=1 || (STATE[0]&0x80))return 0;
    for(unsigned s=0;s<4;++s) {
        if(runtime(s)[22] || get32(INTERNAL+s*76u+4)==0x324f324bu)return 0;
    }
    return 1;
}
static int valid_runtime(volatile uint8_t *r) {
    return r[23]==1 && r[99]==4 && r[20]>=1 && r[20]<=100 &&
           get32(r+4)>=10000 && get32(r+4)<=2000000;
}
static void snapshot(unsigned s,uint8_t *o) {
    volatile Slot *p=ROWS+s;volatile uint8_t *r=runtime(s);
    for(unsigned i=0;i<64;++i)o[i]=0;
    put32(o,0x31444753u);o[4]=s;
    o[5]=p->uid==uid(s)?p->flags:0;o[6]=bound(s,p)?p->profile:0;
    put32(o+8,p->generation);put32(o+12,p->uid);put32(o+16,p->raw_bits);
    put32(o+20,p->tick);put32(o+24,uid(s));put32(o+28,p->revision);
    put32(o+32,get32(r+4));put32(o+36,get32(r));
    o[40]=r[20];o[41]=PERCENT[s];o[42]=r[23];o[43]=r[99];
    if(o[6]) {
        volatile Geometry *g=CATALOG+p->profile-1;
        put16(o+44,g->core10);put16(o+46,g->full10);put32(o+48,g->total);
        o[52]=g->revision!=0;o[53]=1;
    }
    put32(o+56,TICK);o[60]=1;o[61]=HW;o[62]=MANAGER[0];o[63]=BOX;
}
static void catalog(unsigned id,uint8_t *o) {
    volatile Geometry *g=CATALOG+id-1;put32(o,0x31434753u);
    o[4]=id;o[5]=g->revision!=0;put16(o+6,g->core10);put16(o+8,g->full10);
    put16(o+10,0);put32(o+12,g->total);put32(o+16,g->reserved);
}
/* Returns length, -1 invalid/stale/unsupported, -7 busy. SEND is outside mask. */
int sgf_command(const uint8_t *f,uint8_t *o) {
    unsigned sub=f[4];
    if(sub==0x16) {
        if(f[1]!=4)return -1;put32(o,0x31464753u);o[4]=1;o[5]=4;o[6]=4;o[7]=15;
        put16(o+8,64);put16(o+10,20);return 12;
    }
    if((sub==0x17 && f[1]!=5)||(sub==0x18 && f[1]!=19)||
       (sub==0x19 && f[1]!=5)||(sub==0x1a && f[1]!=19)||sub<0x17||sub>0x1a)return -1;
    unsigned n=f[5];if((sub==0x17||sub==0x1a)?n>=4:(n<1||n>4))return -1;
    uint32_t m=lock();int rc=-1;
    if(sub==0x17){snapshot(n,o);rc=64;goto done;}
    if(sub==0x19){catalog(n,o);rc=20;goto done;}
    if(!idle()){rc=-7;goto done;}
    if(sub==0x18) {
        uint32_t rev=get32(f+8),core=get16(f+12),full=get16(f+14),total=get32(f+16);
        if(f[6]||f[7])goto done;
        if(!rev){if(core||full||total)goto done;}
        else if(core<500||core>10000||full<core+100||full>15000||total<10000||total>2000000)goto done;
        volatile Geometry *g=CATALOG+n-1;
        /* Preserve the high-water revision through disable: no ABA reuse. */
        int same=rev && rev==g->revision && core==g->core10 && full==g->full10 && total==g->total;
        if(rev && !same && rev<=g->reserved)goto done;
        g->core10=core;g->full10=full;g->total=total;
        if(rev)g->reserved=rev;g->revision=rev;
        catalog(n,o);rc=20;goto done;
    }
    volatile Slot *p=ROWS+n;volatile uint8_t *r=runtime(n);unsigned id=f[6];
    uint32_t u=uid(n);
    if(f[7]||id>4||!u||get32(f+8)!=u||!p->generation||get32(f+12)!=p->generation||p->uid!=u)goto done;
    if(!id){if(get32(f+16))goto done;p->bound_uid=p->profile=p->revision=p->applied_generation=0;snapshot(n,o);rc=64;goto done;}
    volatile Geometry *g=CATALOG+id-1;
    if(!g->revision||get32(f+16)!=g->revision||!usable(n,p)||!valid_runtime(r))goto done;
    if(p->bound_uid==u && p->profile==id && p->applied_generation==p->generation && p->revision==g->revision) {
        snapshot(n,o);rc=64;goto done; /* Lost ACK cannot reset newer consumption. */
    }
    if(get32(r)){rc=-7;goto done;}
    unsigned value=percent(p->raw_bits,g);
    p->bound_uid=u;p->profile=id;p->revision=g->revision;p->applied_generation=p->generation;
    for(unsigned i=0;i<24;++i)r[i]=0;
    put32(r+4,g->total);r[20]=value;r[23]=1;r[99]=4;PERCENT[n]=value;
    if(STATE[2]==n)STATE[3]=value;
    snapshot(n,o);rc=64;
done:unlock(m);return rc;
}
