#!/usr/bin/env python3
"""Static safety gate for v3.22 first timing hook subset."""
from pathlib import Path
import json,subprocess,hashlib,struct,re,sys
p=Path(__file__).resolve().parent
s=(p/'handler-v3_23.S').read_text();b=(p/'build-v3_23.py').read_text()
fw=(p.parent/'v3.19-volatile-ram'/'cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin').read_bytes()
checks={
 'known_baseline':hashlib.sha256(fw).hexdigest()=='9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff',
 'other_motor_hooks_disabled':'ENABLE_ADVANCED_HOOKS = False' in b,
 'exact_five_hooks_type4_trial': all(x in b for x in ("(0x08011116, 'cfg7_r0_wrapper')", "(0x080112CA, 'cfg8_r1_wrapper')", "(0x08032C72,'cfg20_r7_wrapper')", "(0x08032CEC,'cfg22_cmp_wrapper')", "(0x08013684,'type4_usage_gate_wrapper')")),
 'cfg5_distinct_feature_byte':'movs    r0, #0xE5' in s and 'v323-cfg5t' in s,
 'boot_heap_lower_bound_relocated':"struct.pack_into('<I',image,0x08027960-APP_BASE,0x20006F28)" in b,
 'boot_header_init_hook':"(0x0802A5F2,'heap_init_sidecar_wrapper')" in b and 'str     r1, [r0, #4]' in s,
 'original_heap_limit':struct.unpack_from('<I',fw,0x0802795c-0x08010000)[0]==0x20010000,
 'original_stack_vector':struct.unpack_from('<I',fw,0)[0]==0x20006ee8,
 'ram_reserved_64':'SIDECAR_BASE,      0x20006EE8' in s and 'SIDECAR_SIZE,      64' in s,
 '28_get_values':'CONFIG_V2_COUNT,       28' in s,
 'only_hooked_ids_accept_writes': all(x in s for x in ('cfg5_set_allowed:', 'cfg5_reset_allowed:', 'cmp     r6, #20', 'cmp     r6, #22', 'bne.w   status_bad')),
 'corrected_id17_default':'.hword 400  @ ID 17' in s,
 'type4_hardware_gate_is_slot_scoped': "type4_usage_gate_wrapper:" in s and 'ldrb    r2, [r3, #99]' in s and 'ldrb    r2, [r3, #22]' in s and 'bl      STOCK_REMAIN_GATE' in s,
 'true_ms_id20_id22': '.hword 25000  @ ID 20' in s and '.hword 500  @ ID 22' in s and '.hword 5000, 60000  @ ID 20' in s and '.hword 100, 2000  @ ID 22' in s and 'cfg5_check_tick_division:' in s,
 'true_ms_id8': '.hword 7000  @ ID 8' in s and '.hword 1000, 50000  @ ID 8' in s and 'udiv    r1, r0, r2' in s,
 'reject_non_exact_id8_ms': 'set_time_units_ok:' in s and 'cmp     r1, r7' in s,
 'no_storage_only_ack': "'allowed_v2_write_ids': [1,2,3,5,7,8,20,22]" in b and 'cfg5_set_allowed:' in s,
 'stock_feeder_speeds_remain_readonly':'cmp     r6, #4' in s[s.index('op_config_v2_set:\n'):s.index('op_config_v2_reset:\n')] and 'beq.w   status_bad' in s,
 'stock_hub_speeds_ram_write_only': 'set_stock_speed:' in s and 'strb    r7, [r0, r1]' in s and 'bl      config_ptr' in s,
 'strict_bounds': 'compact_bounds_u16:' in s and len(re.findall(r'\.hword [0-9]+, [0-9]+  @ ID (?:[7-9]|1[0-9]|2[0-7])\b',s))==21,
 'volatile_mask_is_used':'ldr     r2, [r5, #4]' in s and 'str     r0, [r5, #4]' in s,
 'no_nvram_writes':'EEPROM' not in s or 'eeprom writes' not in s.lower(),
 'v323_policy_limit_in_builder': '0x0803D000' in b,
 'no_tag_ops_changed': 'legacy_read0_wrapper:' in s and 'alt_read_wrapper:' in s,
 'strict_original_hook_bytes': 'ORIGINAL_TIMING_MOVW' in b and all(x in b for x in ('4ff44860','4ff42f71','40f2e247','6d1c192d')),
 'verified_original_box_state_address': '.equ BOX_OPER_STATE,     0x200037D0' in s,
 'box_operating_state_guard_for_hub_and_timing': s.count('ldr     r0, box_operating_state_ptr') == 3 and s.count('bne.w   status_busy') == 3,
 'legacy_rfid_state_not_used_by_set_reset': s.count('blo.w   status_busy') == 0,
 'diagnostics_never_authorize_set':'cmp     r6, #CONFIG_V2_COUNT' in s,
 'diagnostic_gets_read_only':'v322_diag_read:' in s and 'ldrh    r0, [r0, r1]' in s,
 'safe_reg_preserving_wrappers': all(x in s for x in ('cfg7_r0_wrapper:', 'cfg8_r1_wrapper:', 'cfg20_r7_wrapper:', 'cfg22_cmp_wrapper:')),
 'no_original_stock_calls_replaced_elsewhere': 'TIMING_HOOKS' in b and 'assert len(patches)==17' in b,
}
assert all(checks.values()),[k for k,v in checks.items() if not v]
obj=Path('/tmp/v323-check.o');elf=Path('/tmp/v323-check.elf')
subprocess.run(['arm-none-eabi-gcc','-c','-mcpu=cortex-m3','-mthumb','-o',str(obj),str(p/'handler-v3_23.S')],check=True)
subprocess.run(['arm-none-eabi-ld','-T',str(p/'link.ld'),'-o',str(elf),str(obj)],check=True)
syms=subprocess.check_output(['arm-none-eabi-nm','-n',str(elf)],text=True)
end=int(re.search(r'^([0-9a-f]+) t handler_end$',syms,re.M).group(1),16)
checks['within_v323_policy_limit']=end<=0x0803D000
result={'pass':all(checks.values()),'checks':checks,'image_end':hex(end),'flash_limit_policy':'nominal 0x0803D000 = real 0x08030000, below the parameter page 0x0807F800','note':'Static checks and ISA emulation cannot establish heap ownership or real MCU safety.'}
(p/'preflight.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));sys.exit(0 if result['pass'] else 1)
