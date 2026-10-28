"""Execute per-slot nominal-length overrides against the candidate ARM code."""
import json,struct
from test_spool_family import FamilyArm,SYMS,UID,u32,expect_readonly_rejection,ROOT
from unicorn.arm_const import UC_ARM_REG_R8
LENGTHS=0x20007068

def payload(a,total,uid=None,slot=None):
    return bytes((0x1c,a.slot if slot is None else slot,0,0))+(a.tag_uid if uid is None else uid)+u32(total)
def length(a):
    status,p=a.command(bytes((0x1b,a.slot)))
    assert status==0 and len(p)==16 and p[:4]==b'SGL1'
    assert p[4]==a.slot and p[6:8]==bytes(2)
    return {'configured':p[5],'uid':p[8:12],'total':struct.unpack_from('<I',p,12)[0]}
def fresh(slot=1,default=0):
    a=FamilyArm(slot);assert a.catalog(total=default)[0]==0;a.scan()
    return a
def set_total(a,total):
    status,p=a.command(payload(a,total));assert status==0
    assert p==a.command(bytes((0x1b,a.slot)))[1]
    return length(a)

def run():
    cases=0;data={}
    a=fresh();assert a.command(b'\x16')[1][7]&0x10
    q=a.query();assert length(a)=={'configured':0,'uid':UID,'total':0}
    expect_readonly_rejection(a,bytes((0x1a,a.slot,1,0))+UID+u32(q['generation'])+u32(1));cases+=1
    before=a.state()
    assert set_total(a,327000)['total']==327000 and a.state()==before
    assert a.bind()[0]==0 and a.query()['total']==327000 and a.query()['initial']==100;cases+=1
    # Retrying length and BIND after a lost reply cannot rewind consumption.
    a.u.mem_write(a.row,u32(2300));before=a.state()
    set_total(a,327000);assert a.bind()[0]==0 and a.state()==before;cases+=1
    expect_readonly_rejection(a,payload(a,330000),7)
    expect_readonly_rejection(a,payload(a,0),7);cases+=2
    # One vendor geometry can serve different lengths on all four slots.
    a=fresh(0)
    lengths=[327000,330000,250000,100000]
    for s,total in enumerate(lengths):
        a.slot=s;a.row=0x20004590+s*100
        r=0x20004460+s*76
        a.u.mem_write(r+60,b'\x04\x00')
        a.u.mem_write(r+74,b'\x08')
        a.set_uid(bytes((1,2,3,s+4)));a.scan()
        assert set_total(a,total)['total']==total
        assert a.bind()[0]==0
        assert a.query()['total']==total and a.query()['profile']==1
        cases+=1
    assert struct.unpack('<8I',a.u.mem_read(LENGTHS,32))[1::2]==tuple(lengths)
    assert a.command(b'\x19\x01')[1][12:16]==bytes(4)
    data['one_vendor_geometry_slot_totals_mm']=lengths
    # A new UID cannot inherit a prior spool's nominal length.
    a=fresh();set_total(a,327000);a.bind()
    a.set_uid(b'\x11\x22\x33\x44')
    assert length(a)['configured']==0 and length(a)['total']==0
    a.scan();assert bytes(a.u.mem_read(LENGTHS+a.slot*8,8))==bytes(8)
    q=a.query();expect_readonly_rejection(a,bytes((0x1a,a.slot,1,0))+a.tag_uid+u32(q['generation'])+u32(1));cases+=1
    assert set_total(a,330000)['total']==330000 and a.bind()[0]==0;cases+=1
    # Fresh scans retain the selected slot length, while changing only the measured anchor.
    a=fresh();set_total(a,327000);a.bind();q=a.scan(460,60)
    assert q['initial']==71 and q['total']==327000 and q['used']==0;cases+=1
    # Compatibility: an old nonzero catalog total is still a valid fallback.
    a=fresh(default=330000);assert a.bind()[0]==0 and a.query()['total']==330000
    assert length(a)['configured']==0;cases+=1
    a=fresh(default=330000);set_total(a,327000);assert a.bind()[0]==0 and a.query()['total']==327000;cases+=1
    # Clearing an unused override does not reset the runtime.
    a=fresh(default=330000);set_total(a,327000);a.bind();before=a.state()
    assert set_total(a,0)['configured']==0 and a.state()==before
    assert a.bind()[0]==0 and a.query()['total']==330000;cases+=1
    for total in [1,9999,2000001,0xffffffff]:
        a=fresh();expect_readonly_rejection(a,payload(a,total));cases+=1
    for total in [10000,2000000]:
        a=fresh();set_total(a,total);assert a.bind()[0]==0 and a.query()['total']==total;cases+=1
    a=fresh()
    bad=[payload(a,327000,uid=b'\x00'*4),payload(a,327000,uid=b'\x09'*4),
         payload(a,327000,slot=4),b'\x1c',payload(a,327000)+b'\x00',
         bytes((0x1c,a.slot,1,0))+UID+u32(327000),
         bytes((0x1c,a.slot,0,1))+UID+u32(327000),b'\x1b\x04',b'\x1b',b'\x1b\x01\x00']
    for p in bad:expect_readonly_rejection(a,p);cases+=1
    for state in [1,2,3,4,5]:
        a=fresh();a.u.mem_write(0x200037d2,bytes((state,)))
        expect_readonly_rejection(a,payload(a,327000),7);cases+=1
    for slot in range(4):
        for mode in (1,2):
            a=fresh();a.u.mem_write(0x20004590+slot*100+22,bytes((mode,)))
            expect_readonly_rejection(a,payload(a,327000),7);cases+=1
    # An IRQ changing the current UID sees either no write or an obsolete keyed write;
    # the getter must never expose that obsolete total as belonging to the new UID.
    a=fresh();a.clear_audit();a.command(payload(a,327000));boundaries=len(a.trace)
    for at in range(1,boundaries+1):
        b=fresh();b.clear_audit();b.injection_at=at
        b.injection=lambda x:x.set_uid(b'\x55\x66\x77\x88')
        status,_=b.command(payload(b,327000,uid=UID))
        assert status in (0,1) and b.delivered is not None
        assert length(b)['configured']==0 and length(b)['total']==0
    data.update(passed=True,cases=cases,uid_change_boundaries=boundaries,no_hardware_access=True)
    (ROOT/'work/build/slot-length-results.json').write_text(json.dumps(data,indent=2)+'\n')
    print(json.dumps(data,indent=2))
if __name__=='__main__':run()
