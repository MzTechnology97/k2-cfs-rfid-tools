#!/usr/bin/env python3
"""Static safety gate for v3.22 first timing hook subset."""
from pathlib import Path
import json,subprocess,hashlib,struct,re,sys
p=Path(__file__).resolve().parent
s=(p/'handler-v3_22.S').read_text();b=(p/'build-v3_22.py').read_text()
fw=(p.parent/'v3.19-volatile-ram'/'cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin').read_bytes()
checks={
 'known_baseline':hashlib.sha256(fw).hexdigest()=='9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff',
 'other_motor_hooks_disabled':'ENABLE_ADVANCED_HOOKS = False' in b,
 'only_two_timing_hooks': "TIMING_HOOKS = [(0x08011116, 'cfg7_r0_wrapper'), (0x080112CA, 'cfg8_r1_wrapper')]" in b,
 'v322_unique_feature_byte':'movs    r0, #0xD7' in s,
 'boot_heap_lower_bound_relocated':"struct.pack_into('<I',image,0x08027960-APP_BASE,0x20006F28)" in b,
 'boot_header_init_hook':"(0x0802A5F2,'heap_init_sidecar_wrapper')" in b and 'str     r1, [r0, #4]' in s,
 'original_heap_limit':struct.unpack_from('<I',fw,0x0802795c-0x08010000)[0]==0x20010000,
 'original_stack_vector':struct.unpack_from('<I',fw,0)[0]==0x20006ee8,
 'ram_reserved_64':'SIDECAR_BASE,      0x20006EE8' in s and 'SIDECAR_SIZE,      64' in s,
 '28_get_values':'CONFIG_V2_COUNT,       28' in s,
 'stock_speed_writes_rejected':'cmp     r6, #7' in s[s.index('op_config_v2_set:\n'):s.index('op_config_v2_reset:\n')],
 'strict_bounds': 'compact_bounds_u16:' in s and len(re.findall(r'\.hword [0-9]+, [0-9]+  @ ID (?:[7-9]|1[0-9]|2[0-7])\b',s))==21,
 'volatile_mask_is_used':'ldr     r2, [r5, #4]' in s and 'str     r0, [r5, #4]' in s,
 'no_nvram_writes':'EEPROM' not in s or 'eeprom writes' not in s.lower(),
 't113_existing_flash_area_cap': '0x0803B800' in b,
 'no_tag_ops_changed': 'legacy_read0_wrapper:' in s and 'alt_read_wrapper:' in s,
 'strict_two_original_movw': 'ORIGINAL_TIMING_MOVW' in b and '4ff44860' in b and '4ff42f71' in b,
 'verified_original_box_state_address': '.equ BOX_OPER_STATE,     0x200037D0' in s,
 'new_guard_exact_two': s.count('ldr     r0, box_operating_state_ptr') == 2 and s.count('bne.w   status_busy') == 2,
 'legacy_rfid_state_not_used_by_set_reset': s.count('blo.w   status_busy') == 0,
 'diagnostics_never_authorize_set':'cmp     r6, #CONFIG_V2_COUNT' in s,
 'diagnostic_gets_read_only':'v322_diag_read:' in s and 'ldrh    r0, [r0, r1]' in s,
 'safe_reg_preserving_wrappers': 'cfg7_r0_wrapper:' in s and 'cfg8_r1_wrapper:' in s,
 'no_original_stock_calls_replaced_elsewhere': b.count("('cfg7_r0_wrapper')") <= 2,
}
assert all(checks.values()),[k for k,v in checks.items() if not v]
obj=Path('/tmp/v322-check.o');elf=Path('/tmp/v322-check.elf')
subprocess.run(['arm-none-eabi-gcc','-c','-mcpu=cortex-m3','-mthumb','-o',str(obj),str(p/'handler-v3_22.S')],check=True)
subprocess.run(['arm-none-eabi-ld','-T',str(p/'link.ld'),'-o',str(elf),str(obj)],check=True)
syms=subprocess.check_output(['arm-none-eabi-nm','-n',str(elf)],text=True)
end=int(re.search(r'^([0-9a-f]+) t handler_end$',syms,re.M).group(1),16)
checks['within_hypothesized_2k_last_sector']=end<=0x0803B800
result={'pass':all(checks.values()),'checks':checks,'image_end':hex(end),'flash_limit_hypothesis':'0x0803B800 NOT HARDWARE VALIDATED','note':'Static checks and ISA emulation cannot establish heap ownership or real MCU safety.'}
(p/'preflight.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));sys.exit(0 if result['pass'] else 1)
