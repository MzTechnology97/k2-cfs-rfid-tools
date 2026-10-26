#!/usr/bin/env python3
"""Rebuild CFG6 DIAG1 and run ISA regressions; NEVER accesses MCU hardware."""
from pathlib import Path
import hashlib,subprocess,sys,tempfile,struct
from decode_diag1 import decode,STOCK_RAW_TO_MM
HERE=Path(__file__).resolve().parent
REF=HERE/"CFG6-READONLY-DIAG1-NOT-FOR-FLASH.bin"
BASE=HERE.parent/"v3.19-volatile-ram/cfs0_050_G32-cfs0_000_153-runtime-config-v3_13.bin"
EXPECTED="6f07d792ad5fc6f402167a2aa1fe9c7b67df93dc558ac685176767a23b23a520"
SCRIPTS=["test_diag1_patch_scope.py","test_readonly_diag1.py","test_type4_rescan_preserves_print.py",
 "test_stock_odometer_sign.py","emulate_v3_23.py","test_type4_gate.py",
 "test_type4_accounting_fullpath.py","test_type4_print_start_end.py",
 "test_cfg5_abi.py","test_cfg6_abi.py"]
assert hashlib.sha256(REF.read_bytes()).hexdigest()==EXPECTED
with tempfile.TemporaryDirectory(prefix="cfg6-diag1-") as temp:
 out=Path(temp)/"candidate.bin"
 subprocess.run([sys.executable,str(HERE/"build-v3_23.py"),"--base",str(BASE),
                 "--out",str(out)],cwd=HERE,check=True,capture_output=True)
 assert out.read_bytes()==REF.read_bytes(),"Non-reproducible LAB build"
 print("PASS: clean build, byte identity, SHA256")
 for script in SCRIPTS:
  args=[sys.executable,str(HERE/script)]
  if script=="emulate_v3_23.py":args.append(str(REF))
  result=subprocess.run(args,cwd=HERE,capture_output=True,text=True)
  if result.returncode:
   print(result.stdout[-1800:],result.stderr[-1800:])
   raise SystemExit("FAILED: "+script)
  print("PASS:",script)
 packet=struct.pack("<4s8BIIff4B",b"RDG1",2,2,2,0,1,4,1,0,
                    7900,330000,497500.0,-498001.5,60,60,1,0)
 decoded=decode(packet)
 assert decoded["type4_gate_conditions_allow"] is True
 assert decoded["cfs_percent_table"]==60
 assert abs(decoded["odometer_normalized_current_approx_mm"] -
            498001.5*STOCK_RAW_TO_MM)<1e-5
 assert abs(decoded["odometer_delta_since_checkpoint_approx_mm"] -
            (498001.5*STOCK_RAW_TO_MM-497500.0))<1e-5
 print("PASS: offline decoder")
print("ALL OFFLINE TESTS PASSED; NOT HARDWARE-VALIDATED; NOT FOR FLASH.")
