/* RH1: bounded host-key handoff in the existing OEM RFID worker.
 * Command handlers enqueue work only. No command-thread RF or motor call. */
#include <stdint.h>
#include <stddef.h>
#define RH ((volatile Handoff *)0x20007088u)
#define INTERNAL ((volatile uint8_t *)0x20004460u)
#define ROWS ((volatile uint32_t *)0x20006F28u)
#define RUNTIME ((volatile uint8_t *)0x20004590u)
#define MANAGER (*(volatile uint8_t *)0x2000391Cu)
#define BOX (*(volatile uint8_t *)0x200037D2u)
#define STATE ((volatile uint8_t *)0x200001F0u)
#define CONTROL ((volatile uint8_t *)0x20000024u)
#define TICK (*(volatile uint32_t *)0x200009E4u)
#define HW (*(volatile uint8_t *)0x20000000u)
#define NOMINAL_CODE_BIAS 0xD000u
/* Analysis/assembler coordinates are nominal; an indirect Thumb pointer is
 * absolute and must use the application actual base 0x08003000. */
#define FN(addr,type) ((type)(((addr)-NOMINAL_CODE_BIAS)|1u))
typedef struct {
    uint32_t session,token,request,uid,lease_tick,wait_tick,wait_ms,lease_ms;
    uint32_t last_request;
    uint8_t enabled,state,slot,result,leased,job,attempted,last_slot;
    uint8_t keys[18],padding[34];
} Handoff;
_Static_assert(sizeof(Handoff)==96,"RH1 reserved SRAM");
extern void sgf_prepare_handoff(unsigned slot);
static uint32_t lock(void) { uint32_t m;__asm__ volatile("mrs %0,primask\n cpsid i":"=r"(m)::"memory");return m; }
static void unlock(uint32_t m) { __asm__ volatile("msr primask,%0"::"r"(m):"memory"); }
static uint32_t get32(const volatile uint8_t *p) { return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static unsigned get16(const uint8_t *p) { return p[0]|((unsigned)p[1]<<8); }
static uint32_t uid(unsigned s) {
    volatile uint8_t *r=INTERNAL+s*76u;
    return s<4 && r[60]==4 && !r[61] && r[74]==8 ? get32(r+62):0;
}
static int leased(void) { return RH->enabled && RH->leased && (uint32_t)(TICK-RH->lease_tick)<RH->lease_ms; }
int rfh_busy(void) { return RH->state>=1 && RH->state<=3; }
/* Retain the short lock until the legacy scratch writer restores PRIMASK. */
uint32_t rfh_key_guard(void) { uint32_t m=lock();if(rfh_busy()){unlock(m);return ~0u;}return m; }
static int idle(void) {
    if(BOX || MANAGER!=1 || (STATE[0]&0x80) || rfh_busy())return 0;
    for(unsigned s=0;s<4;++s)if(RUNTIME[s*100u+22] || get32(INTERNAL+s*76u+4)==0x324f324bu)return 0;
    return 1;
}
/* Only this periodic worker hook performs async job completion cleanup.
 * The OEM tail has set both idle states before we restore its saved flag. */
void rfh_tick(void) {
    uint32_t m=lock();
    if(RH->state==1 && MANAGER==1 && !BOX) {
        if(RH->job) {
            FN(0x08012358u,void (*)(void))();RH->job=0;
        }
        RH->state=4;if(!RH->result)RH->result=5;
    }
    unlock(m);
}
void rfh_begin(unsigned s) {
    uint32_t m=lock();
    if(s<4 && leased()) {
        if(!RH->job)RH->request=0;
        RH->slot=s;RH->uid=0;RH->result=0;RH->attempted=0;RH->state=1;
    }
    unlock(m);
}
static void snapshot(uint8_t *out) {
    uint32_t *o=(uint32_t *)out;uint32_t now=TICK;
    o[0]=0x314f4852u;o[1]=1u|((uint32_t)RH->state<<8)|((uint32_t)RH->slot<<16)|((uint32_t)RH->result<<24);
    o[2]=RH->session;o[3]=RH->token;o[4]=RH->request;o[5]=RH->uid;
    uint32_t elapsed=now-RH->wait_tick;
    o[6]=RH->state==2 && elapsed<RH->wait_ms?RH->wait_ms-elapsed:0;
    o[7]=RH->enabled|(leased()?2u:0u)|(RH->job?4u:0u);
    o[8]=RH->slot<4?ROWS[RH->slot*16u]:0;o[9]=now;
}
int rfh_command(const uint8_t *f,uint8_t *out) {
    unsigned op=f[4],n=f[1];int result=-1;uint32_t m=lock();
    if(op==0x20 && n==4) {
        uint32_t *o=(uint32_t *)out;o[0]=0x31494852u;o[1]=0x07042801u;o[2]=5000u|(10000u<<16);result=12;goto done;
    }
    if(n<11)goto done;
    uint32_t session=get32(f+8);
    if(op==0x21 && n==15) {
        unsigned wait=get16(f+12),lease=get16(f+14);
        if(f[5]>1 || f[6] || f[7] || !session || wait<500 || wait>5000 || lease<1000 || lease>10000)goto done;
        if(f[5] && HW)goto done;
        if(!idle()){result=-7;goto done;}
        if(RH->session!=session)RH->last_request=0;
        RH->session=session;RH->enabled=f[5];RH->wait_ms=wait;RH->lease_ms=lease;
        RH->leased=0;RH->state=0;RH->result=0;RH->request=0;RH->uid=0;RH->slot=255;goto state;
    }
    if(!session || session!=RH->session || !RH->enabled)goto done;
    if(op==0x23 && n==11 && !f[5] && !f[6] && !f[7]) {
        RH->lease_tick=TICK;RH->leased=1;goto state;
    }
    if(op==0x22 && n==15) {
        unsigned s=f[5];uint32_t request=get32(f+12);
        if(s>=4 || f[6] || f[7] || !request || HW)goto done;
        if(request==RH->last_request) { if(s!=RH->last_slot)goto done;goto state; }
        if(!leased())goto done;
        if(!idle() || !FN(0x0801B79Cu,unsigned (*)(unsigned))(0) ||
           !FN(0x0801B79Cu,unsigned (*)(unsigned))(1) || !FN(0x0801B79Cu,unsigned (*)(unsigned))(2) ||
           !FN(0x0801B79Cu,unsigned (*)(unsigned))(3) ||
           FN(0x0801B78Cu,unsigned (*)(unsigned))(s)) {result=-7;goto done;}
        RH->slot=s;RH->uid=0;RH->request=request;RH->last_request=request;RH->last_slot=s;
        RH->result=0;RH->attempted=0;RH->job=1;RH->state=1;
        ((volatile uint8_t *)0x20000030u)[s]=1;
        FN(0x0801233Cu,void (*)(unsigned,unsigned))(s,1);goto state;
    }
    if((op==0x24 && n==37) || (op==0x25 && n==19)) {
        if(f[6] || f[7] || (RH->state!=2 && !(op==0x24 && RH->state==3)) || !leased() ||
           (RH->state==2 && (uint32_t)(TICK-RH->wait_tick)>=RH->wait_ms) || f[5]!=RH->slot ||
           get32(f+12)!=RH->token || get32(f+16)!=RH->uid || uid(RH->slot)!=RH->uid)goto done;
        if(RH->state==3) {for(unsigned i=0;i<18;++i)if(RH->keys[i]!=f[20+i])goto done;goto state;}
        if(op==0x25){RH->result=3;RH->state=1;}
        else {for(unsigned i=0;i<18;++i)RH->keys[i]=f[20+i];RH->state=3;}
        goto state;
    }
    goto done;
state:snapshot(out);result=40;
done:unlock(m);return result;
}
static int complete(unsigned s) {
    volatile uint8_t *r=INTERNAL+s*76u;
    volatile uint32_t *p=ROWS+s*16u;uint32_t u=uid(s);
    return u && p[11]==u && p[12]==7 && !p[13] && p[15] &&
        r[9]==7 && r[10]==7 && !r[11] && get32(r+12)==0x4c52324bu &&
        get32(INTERNAL+((s+2u)&3u)*76u+4)==0x3343324bu &&
        get32(INTERNAL+((s+3u)&3u)*76u+4)==0x3344324bu;
}
static void arm(unsigned s) {
    for(unsigned j=0;j<4;++j)for(unsigned i=4;i<20;++i)INTERNAL[j*76u+i]=0;
    sgf_prepare_handoff(s);
    volatile uint8_t *r=INTERNAL+s*76u,*next=INTERNAL+((s+1u)&3u)*76u;
    for(unsigned i=0;i<18;++i) {
        if(i<6)r[12+i]=RH->keys[i];else next[i-2]=RH->keys[i];RH->keys[i]=0;
    }
    *(volatile uint32_t *)(next+16)=0x324e324bu;r[8]=3;
    *(volatile uint32_t *)(r+4)=0x324f324bu;
}
/* Same ABI and original validator first. S16/S17 contain OEM odometers here;
 * integer-only C preserves them. The absolute circumference is computed later. */
unsigned rfh_validate(unsigned reader,unsigned reader_slot,unsigned attempts) {
    unsigned s=reader*2u+reader_slot;
    int armed=0;
    for(unsigned i=0;i<4;++i)if(get32(INTERNAL+i*76u+4)==0x324f324bu)armed=1;
    unsigned result=FN(0x0801A670u,unsigned (*)(unsigned,unsigned,unsigned))(reader,reader_slot,attempts);
    if(s>=4)return result;
    int tracked=RH->state==1 && RH->slot==s;
    if(complete(s)){if(tracked)RH->result=2;return 0;}
    if(!result){if(tracked)RH->result=1;return 0;}
    uint32_t m=lock();
    if(armed || HW || RH->slot!=s || RH->state!=1 || RH->attempted || !leased() || !uid(s) || m) {unlock(m);return result;}
    RH->attempted=1;RH->uid=uid(s);RH->token=RH->token==0xffffffffu?1:RH->token+1;
    RH->wait_tick=TICK;RH->state=2;unlock(m);
    for(;;) {
        m=lock();
        if(RH->state!=2)break;
        if(!leased() || (uint32_t)(TICK-RH->wait_tick)>=RH->wait_ms || uid(s)!=RH->uid) {
            RH->result=4;RH->state=1;break;
        }
        unlock(m);FN(0x0802EE28u,void (*)(unsigned))(10);
    }
    if(RH->state!=3){unlock(m);return result;}
    if(!leased() || uid(s)!=RH->uid) {RH->result=4;RH->state=1;unlock(m);return result;}
    arm(s);RH->state=1;unlock(m);
    FN(0x0801959Eu,void (*)(unsigned,unsigned))(reader,reader_slot);
    result=FN(0x0801A670u,unsigned (*)(unsigned,unsigned,unsigned))(reader,reader_slot,attempts);
    if(complete(s)){RH->result=2;return 0;}
    RH->result=result?5:1;return result;
}
