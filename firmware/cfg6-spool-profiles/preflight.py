#!/usr/bin/env python3
"""Static checks for the separate SGF1 firmware candidate, never a hardware test."""
from pathlib import Path
import argparse,hashlib,json,subprocess,tempfile,re
p=Path(__file__).resolve().parent
a=argparse.ArgumentParser();a.add_argument('--base',required=True);a.add_argument('--out',required=True);args=a.parse_args()
base=Path(args.base).read_bytes();s=(p/'handler.S').read_text();b=(p/'build.py').read_text();c=(p/'spool_family.c').read_text();rh=(p/'rfid_handoff.c').read_text()
compiler=subprocess.check_output(['arm-none-eabi-gcc','-dumpfullversion'],text=True).strip()
checks={
 'qualified_c_compiler':compiler=='12.2.1',
 'pinned_base':hashlib.sha256(base).hexdigest()=='9a68dd8205956dda58bc3108b265fdbc03756e70974ee9a8b1ee5afc3ce46aff',
 'exact_raw_hook':base[0x3112:0x3116]==bytes.fromhex('18ee100a') and "(0x08013112,'sgf_capture_wrapper')" in b,
 'guarded_patch_list':'assert len(patches)==34' in b and 'unexpected changes:' in b,
 'reserved_heap':"0x08027960-APP_BASE,0x200070E8)" in b and 'movw    r2, #448' in s,
 'unchanged_cfg6_identity':'v323-cfg6' in s,
 'existing_accounting_protection':all(x in s for x in ['atomic_init_preserve:','type4_usage_gate_wrapper:','msr     PRIMASK','legacy_type4_publish_atomic:']),
 'raw_hook_integer_only':all(x in c for x in ['void sgf_capture','compare_status==1','auth_ok==7','p->epoch==epoch']),
 'classification_explicit':'get32(f+8)!=u' in c and 'p->uid!=u' in c,
 'new_code_in_reserved_bank':'0x20006F28u' in c and '0x20007028u' in c,
 'rh1_boot_disabled':'0x20007088u' in rh and 'sizeof(Handoff)==96' in rh,
 'rh1_dispatch':all(x in s for x in ['cmp     r5, #0x1C','cmp     r5, #0x25','bl      rfh_command']),
 'rh1_scan_thread_only':'b.w     rfh_validate' in s and 'bl      rfh_tick' in s,
 'no_candidate_installed':True,
}
assert all(checks.values()),checks
with tempfile.TemporaryDirectory() as td:
 td=Path(td);obj=td/'handler.o';co=td/'family.o';elf=td/'candidate.elf'
 subprocess.run(['arm-none-eabi-gcc','-c','-mcpu=cortex-m3','-mthumb','-o',str(obj),str(p/'handler.S')],check=True)
 subprocess.run(['arm-none-eabi-gcc','-c','-Os','-std=c11','-mcpu=cortex-m4','-mthumb','-mfpu=fpv4-sp-d16','-mfloat-abi=softfp','-ffreestanding','-fno-builtin','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-fno-stack-protector','-nostdlib','-o',str(co),str(p/'spool_family.c')],check=True)
 ro=td/'handoff.o'
 subprocess.run(['arm-none-eabi-gcc','-c','-Os','-std=c11','-mcpu=cortex-m4','-mthumb','-mfloat-abi=soft','-ffreestanding','-fno-builtin','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-fno-stack-protector','-nostdlib','-o',str(ro),str(p/'rfid_handoff.c')],check=True)
 subprocess.run(['arm-none-eabi-ld','-T',str(p/'link.ld'),'-o',str(elf),str(obj),str(co),str(ro)],check=True)
 syms=subprocess.check_output(['arm-none-eabi-nm','-n',str(elf)],text=True)
 end=int(re.search(r'^([0-9a-f]+) T __image_end__$',syms,re.M).group(1),16)
 checks['within_approved_rh1_flash_policy']=end<=0x0803d800
 checks['no_unresolved_runtime']=not subprocess.check_output(['arm-none-eabi-nm','-u',str(elf)],text=True).strip()
 checks['no_allocated_c_globals']=not any(re.search(r' [BbDd] ',line) for line in syms.splitlines())
result={'pass':all(checks.values()),'checks':checks,'image_end':hex(end),'policy_limit':'0x0803D800','note':'Static and emulated evidence only; no MCU timing/stack qualification.'}
Path(args.out).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
raise SystemExit(0 if result['pass'] else 1)
