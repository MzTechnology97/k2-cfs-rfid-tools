#!/usr/bin/env python3
import argparse, hashlib, pathlib, struct, subprocess, tempfile, json

APP_BASE=0x08010000
HANDLER_ADDR=0x0803AE38
CRC_OFF=0x20C
LEN_OFF=0x20E
META_END=0x212
ENABLE_ADVANCED_HOOKS = False  # All other 20 advanced motor/RFID hooks remain DISABLED.
TIMING_HOOKS = [(0x08011116, 'cfg7_r0_wrapper'), (0x080112CA, 'cfg8_r1_wrapper')]
ORIGINAL_TIMING_MOVW = {
    0x08011116: bytes.fromhex('4ff44860'), # mov.w r0, #3200
    0x080112CA: bytes.fromhex('4ff42f71'), # mov.w r1, #700
}
EXPECTED_BASE_SHA='9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff'

def run(*a): subprocess.check_call(list(map(str,a)))
def output(*a): return subprocess.check_output(list(map(str,a)),text=True)
def crc16_bypass(data):
    crc=0
    for value in data:
        crc ^= value<<8
        for _ in range(8):
            crc=(((crc<<1)^0x8005)&0xffff) if crc&0x8000 else ((crc<<1)&0xffff)
    return crc
def symbols(elf):
    d={}
    for line in output('arm-none-eabi-nm','-n',elf).splitlines():
        p=line.split()
        if len(p)==3:
            try:d[p[2]]=int(p[0],16)
            except ValueError:pass
    return d
def thumb_bl(src,dst):
    with tempfile.TemporaryDirectory() as td:
        td=pathlib.Path(td)
        (td/'x.S').write_text('.syntax unified\n.thumb\n.cpu cortex-m3\n.section .text,"ax",%%progbits\n.global x\n.thumb_func\nx:\n bl 0x%08x\n'%dst)
        (td/'x.ld').write_text('SECTIONS { . = 0x%08x; .text : { *(.text) } }\n'%src)
        run('arm-none-eabi-gcc','-c','-mcpu=cortex-m3','-mthumb','-ffreestanding','-nostdlib','-o',td/'x.o',td/'x.S')
        run('arm-none-eabi-ld','-T',td/'x.ld','-o',td/'x.elf',td/'x.o')
        run('arm-none-eabi-objcopy','-O','binary',td/'x.elf',td/'x.bin')
        b=(td/'x.bin').read_bytes()
        if len(b)!=4: raise RuntimeError('bad BL size')
        return b

def main():
    # Safety interlock: never produce a flashable BIN from unvalidated staging.
    # Bench-only generation after ALL automated preflight checks; production gate remains blocked.
    gate=pathlib.Path(__file__).resolve().parent/'bench_preflight_v3_22.py'
    approval=subprocess.run(['python3',str(gate)],capture_output=True,text=True)
    if approval.returncode:
        raise SystemExit('EXPERIMENTAL BUILD PRECHECK FAILED; no BIN generated.\n'+approval.stdout)
    ap=argparse.ArgumentParser()
    ap.add_argument('--base',required=True)
    ap.add_argument('--out',required=True)
    args=ap.parse_args()
    here=pathlib.Path(__file__).resolve().parent
    base=pathlib.Path(args.base).read_bytes()
    if hashlib.sha256(base).hexdigest()!=EXPECTED_BASE_SHA:
        raise SystemExit('unexpected v3.13 base')
    off=HANDLER_ADDR-APP_BASE

    obj=here/'handler-v3_22.o'; elf=here/'handler-v3_22.elf'; raw=here/'handler-v3_22.bin'
    run('arm-none-eabi-gcc','-c','-mcpu=cortex-m3','-mthumb','-ffreestanding','-nostdlib','-o',obj,here/'handler-v3_22.S')
    run('arm-none-eabi-ld','-T',here/'link.ld','-o',elf,obj)
    run('arm-none-eabi-objcopy','-O','binary',elf,raw)
    handler=raw.read_bytes(); syms=symbols(elf)
    image=bytearray(base[:off]+handler)

    core_patches=[
      (0x0801A4CC,'legacy_read0_wrapper'),
      (0x0801A52C,'legacy_read1_wrapper'),
      (0x0801A590,'legacy_read2_wrapper'),
      (0x080225D0,'alt_read_wrapper'),
      (0x08022604,'alt_read_wrapper'),
      (0x08022638,'alt_read_wrapper'),
      (0x08012DDC,'uid_compare_wrapper'),
      (0x08012E62,'msg_validate_wrapper'),
      (0x08013380,'remaining_gate_wrapper'),
      (0x08013394,'remaining_init_wrapper'),
      (0x0801BF9E,'remaining_valid_wrapper'),

    ]
    # Advanced hooks are intentionally excluded from the read-only baseline.
    # Do not enable these until writable storage and all hook flows are proven.
    advanced_patches=[
      (0x08011116,'cfg7_r0_wrapper'),
      (0x080112CA,'cfg8_r1_wrapper'),
      (0x08011CB6,'cfg9_r1_wrapper'),
      (0x08011E14,'cfg10_r1_wrapper'),
      (0x08012A9E,'rfid_seek_speed_call_wrapper'),
      (0x08012AC0,'rfid_measure_speed_call_wrapper'),
      (0x08012E8A,'rfid_reposition_speed_call_wrapper'),
      (0x08012A76,'cfg14_r5_wrapper'),
      (0x08012AAE,'rfid_seek_settle_call_wrapper'),
      (0x08012E7A,'rfid_post_auth_wait_call_wrapper'),
      (0x08012E84,'rfid_pre_measure_settle_call_wrapper'),
      (0x0801304A,'cfg18_r7_wrapper'),
      (0x08013078,'rfid_neighbor_settle_call_wrapper'),
      (0x08032C72,'cfg20_r7_wrapper'),
      (0x08032D46,'cfg21_r1_wrapper'),
      (0x08032DAC,'cfg21_r1_wrapper'),
      (0x08032CEC,'odometer_stall_cmp_wrapper'),
      (0x0801307C,'rfid_neighbor_retry_cmp_wrapper'),
      (0x080108F0,'reverse_detooth_timeout_cmp_wrapper'),
      (0x08011E5C,'cfg25_r1_wrapper'),
      (0x080112E6,'cfg26_r8_wrapper'),
      (0x080112B6,'cfg27_load_retry_setup'),
    ]
    patches = core_patches + TIMING_HOOKS + (advanced_patches if ENABLE_ADVANCED_HOOKS else []) + [(0x0802A5F2,'heap_init_sidecar_wrapper')]
    assert len(patches)==14 and len(set(x[0] for x in patches))==14
    for callsite, name in TIMING_HOOKS:
        expected=ORIGINAL_TIMING_MOVW[callsite]
        assert base[callsite-APP_BASE:callsite-APP_BASE+4]==expected, (hex(callsite), name)
    report=[]
    for callsite,name in patches:
        target=syms[name]
        pos=callsite-APP_BASE
        before=bytes(image[pos:pos+4])
        patch=thumb_bl(callsite,target)
        image[pos:pos+4]=patch
        report.append((callsite,name,target,before.hex(),patch.hex()))

    assert struct.unpack_from('<I',image,0x08027960-APP_BASE)[0] == 0x20006EE8
    struct.pack_into('<I',image,0x08027960-APP_BASE,0x20006F28)
    struct.pack_into('<I',image,LEN_OFF,len(image))
    check=bytearray(image); check[CRC_OFF:META_END]=b'\0'*(META_END-CRC_OFF)
    crc=crc16_bypass(check)
    struct.pack_into('<H',image,CRC_OFF,crc)
    struct.pack_into('<I',image,LEN_OFF,len(image))
    if APP_BASE+len(image)>0x0803B800:
        raise SystemExit('OVERFLOW: image would exceed 0x0803B800 proven compact region; not built')
    pathlib.Path(args.out).write_bytes(image)

    allowed=set(range(CRC_OFF,META_END))
    allowed.update(range(0x08027960-APP_BASE,0x08027964-APP_BASE))
    for a,_,_,_,_ in report:
        allowed.update(range(a-APP_BASE,a-APP_BASE+4))
    allowed.update(range(off,max(len(base),len(image))))
    changed=[i for i in range(min(len(base),len(image))) if base[i]!=image[i]]
    unexpected=[i for i in changed if i not in allowed]
    if unexpected:
        raise SystemExit('unexpected changes: '+','.join(hex(APP_BASE+i) for i in unexpected[:16]))

    v={
      'base_v313_sha256':hashlib.sha256(base).hexdigest(),
      'sha256':hashlib.sha256(image).hexdigest(),
      'size':len(image),'handler_size':len(handler),'crc16':'0x%04X'%crc,
      'handler_addr':'0x%08X'%HANDLER_ADDR,
      'nominal_total_mm':330000,
      'initial_percent_source':'stock area_percent; K2RL pre-geometry latch + gate override at 0x08013380 + recover 0x20003974+slot when r9 passes 0xFF',
      'runtime_type':4,
      'runtime_config_api':{
        'opcode':'0x57',
        'legacy_v1_subcommands':{'info':'0x0D','set':'0x0E','reset':'0x0F'},
        'v2_subcommands':{
          'info':'0x10','get':'0x11','set':'0x12',
          'reset':'0x13','describe':'0x14',
        },
        'layout_version':2,
        'catalog_revision':1,
        'parameter_count':28,
        'capability_mask': '0xD7',
        'mode': 'EXPERIMENTAL_TIMING_ID7_ID8_SAFE_BOX_STATE_GUARD',
        'v2_writes_enabled': True,
        'v1_speed_writes_enabled': False,
        'advanced_hook_patches_enabled': ENABLE_ADVANCED_HOOKS,
        'advanced_storage': '64 byte boot-cleared RAM sidecar; all 21 writable; only 7/8 hooked to stock execution',
        'parameters':[
          {'id':0,'name':'feeder_forward_speed','type':'raw_u8','default':255,'min':1,'max':255,'flags':['safe']},
          {'id':1,'name':'hub_forward_speed','type':'raw_u8','default':100,'min':1,'max':255,'flags':['safe']},
          {'id':2,'name':'hub_transition_speed','type':'raw_u8','default':200,'min':1,'max':255,'flags':['safe']},
          {'id':3,'name':'hub_insert_speed','type':'raw_u8','default':155,'min':1,'max':255,'flags':['safe']},
          {'id':4,'name':'feeder_reverse_speed','type':'raw_u8','default':255,'min':1,'max':255,'flags':['safe']},
          {'id':5,'name':'hub_reverse_speed','type':'raw_u8','default':80,'min':1,'max':255,'flags':['safe']},
          {'id':6,'name':'reverse_detooth_enable','type':'bool','default':'captured-stock','min':0,'max':1,'flags':['advanced']},
          {'id':7,'name':'hub_transition_wait_ms','type':'milliseconds_u16','default':3200,'min':100,'max':10000,'flags':['advanced','safety-limit']},
          {'id':8,'name':'insert_sensor_timeout_ms','type':'milliseconds_u16','default':700,'min':100,'max':5000,'flags':['advanced','safety-limit']},
          {'id':9,'name':'hub_pullback_timeout_ms','type':'milliseconds_u16','default':5000,'min':500,'max':15000,'flags':['advanced','safety-limit']},
          {'id':10,'name':'unload_sensor_timeout_ms','type':'milliseconds_u16','default':1000,'min':100,'max':5000,'flags':['advanced','safety-limit']},
          {'id':11,'name':'rfid_seek_speed','type':'raw_u8','default':160,'min':1,'max':255,'flags':['advanced','rfid-sensitive']},
          {'id':12,'name':'rfid_measure_speed','type':'raw_u8','default':120,'min':1,'max':255,'flags':['advanced','rfid-sensitive']},
          {'id':13,'name':'rfid_reposition_speed','type':'raw_u8','default':100,'min':1,'max':255,'flags':['advanced','rfid-sensitive']},
          {'id':14,'name':'rfid_seek_move_ms','type':'milliseconds_u16','default':800,'min':100,'max':5000,'flags':['advanced','rfid-sensitive']},
          {'id':15,'name':'rfid_seek_settle_ms','type':'milliseconds_u16','default':200,'min':10,'max':2000,'flags':['advanced','rfid-sensitive']},
          {'id':16,'name':'rfid_post_auth_wait_ms','type':'milliseconds_u16','default':1000,'min':100,'max':5000,'flags':['advanced','rfid-sensitive']},
          {'id':17,'name':'rfid_pre_measure_settle_ms','type':'milliseconds_u16','default':10,'min':1,'max':1000,'flags':['advanced','rfid-sensitive']},
          {'id':18,'name':'rfid_neighbor_detect_delay_ms','type':'milliseconds_u16','default':400,'min':50,'max':2000,'flags':['advanced','rfid-sensitive']},
          {'id':19,'name':'rfid_neighbor_settle_ms','type':'milliseconds_u16','default':100,'min':10,'max':1000,'flags':['advanced','rfid-sensitive']},
          {'id':20,'name':'feed_total_timeout_20ms_ticks','type':'ticks_20ms_u16','default':1250,'min':250,'max':3000,'flags':['advanced','safety-limit']},
          {'id':21,'name':'feed_recovery_timeout_ms','type':'milliseconds_u16','default':3000,'min':500,'max':10000,'flags':['advanced','safety-limit']},
          {'id':22,'name':'odometer_stall_20ms_ticks','type':'ticks_20ms_u16','default':25,'min':5,'max':100,'flags':['advanced','safety-limit']},
          {'id':23,'name':'rfid_neighbor_retry_count','type':'count_u16','default':3,'min':1,'max':10,'flags':['advanced','rfid-sensitive']},
          {'id':24,'name':'reverse_detooth_timeout_ms','type':'milliseconds_u16','default':1000,'min':100,'max':10000,'flags':['advanced','safety-limit']},
          {'id':25,'name':'buffer_fill_timeout_ms','type':'milliseconds_u16','default':30000,'min':1000,'max':60000,'flags':['advanced','safety-limit']},
          {'id':26,'name':'transition_detect_timeout_ms','type':'milliseconds_u16','default':300,'min':50,'max':5000,'flags':['advanced','safety-limit']},
          {'id':27,'name':'load_retry_count','type':'count_u16','default':3,'min':1,'max':10,'flags':['advanced','safety-limit']},
        ],
        'stock_table_offsets':[1,2,3,5,6,7],
        'expected_stock_table_ptr':'0x200037E2',
        'idle_guard':'EXPERIMENTAL: stock BOX_STATE == 0; known unsafe as a complete motor-active guard',
      },
      'patches':[{'callsite':'0x%08X'%a,'symbol':n,'target':'0x%08X'%t,'before':bef,'after':aft} for a,n,t,bef,aft in report],
      'unexpected_changed_bytes':len(unexpected),
      'tag_writes_added':False,
      'release_gate_required':True,
      'production_release_approved':False,
      'experimental_test_only':True,
      'cfs_runtime_diag_read_only': False,
      'v322_timing_hooks': [7,8],
      'v322_hook_addresses': ['0x08011116','0x080112CA'],
      'v322_advanced_volatile_only': True,
      'v322_other_motion_hooks_enabled': False,
      'v319_heap_start': '0x20006F28',
      'v322_flash_end_limit': '0x0803B800',
      'v322_diag': '21 advanced RAM overrides, two stock timing callsites hooked (IDs 7/8), remaining 19 advanced settings not applied, no RFID motor hooks',
      'active_advanced_motion_hooks': [7,8],
      'never_flash_automatically':True,
      'eeprom_writes_added':False,
      'host_extra_for_runtime_config':'klippy/extras/box_cfs_runtime.py',
    }
    (here/'static-validation.json').write_text(json.dumps(v,indent=2)+'\n')
    print(json.dumps(v,indent=2))

if __name__=='__main__': main()
