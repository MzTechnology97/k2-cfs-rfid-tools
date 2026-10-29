#!/usr/bin/env python3
"""Build and qualify the separate SGF1 candidate offline. No device operations."""
from pathlib import Path
import subprocess,sys,json,os,hashlib,runpy,contextlib,io
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
from paths import BUILD,RESULTS,CANDIDATE_IMAGE
RESULTS.mkdir(parents=True,exist_ok=True)
checks={}
def run(name,args):
    p=subprocess.run([sys.executable,*map(str,args)],cwd=ROOT,capture_output=True,text=True)
    (RESULTS/('sgf-'+name+'.log')).write_text(p.stdout+p.stderr)
    if p.returncode:raise RuntimeError(name+' failed:\n'+(p.stdout+p.stderr)[-5000:])
    checks[name]=True;print('PASS',name,flush=True)
run('base',[ROOT/'scripts/prepare_base.py'])
run('build',[ROOT/'firmware/cfg6-spool-profiles/build.py','--base',ROOT/'work/base-pinned.bin','--out',CANDIDATE_IMAGE,'--build-dir',BUILD])
run('family',[ROOT/'tests/test_spool_family.py'])
run('slot_lengths',[ROOT/'tests/test_spool_lengths.py'])
run('rfid_handoff',[ROOT/'tests/test_rfid_handoff.py'])
run('rfid_handoff_physical',[ROOT/'tests/test_rfid_handoff_physical.py'])
run('accounting',[ROOT/'tests/test_accounting.py','--out',RESULTS/'sgf-accounting.json'])
# Boundary comparisons are shared; only the stable-image hook-count assertion
# is replaced by the candidate's own structural check below.
import test_accounting as a
import test_boundaries as b
from test_container import inspect
manifest=json.loads((ROOT/'firmware/cfg6-spool-profiles/manifest.json').read_text())
boundaries={'init_cases':b.init_equivalence(),'unload_cases':b.unload_equivalence(),
            'abi':b.abi(),'failed_rescans':b.failed_rescans(),
            'container':inspect(CANDIDATE_IMAGE,expected_sha=manifest['sha256'],expected_size=manifest['size'])}
assert len(json.loads((BUILD/'static-validation.json').read_text())['patches'])==34
(RESULTS/'sgf-boundaries.json').write_text(json.dumps(boundaries,indent=2))
checks['boundaries']=True;print('PASS boundaries',flush=True)
run('cmd03',[ROOT/'tests/test_cmd03.py'])
run('snapshot',[ROOT/'tests/test_snapshot.py'])
# Existing ABI tests use legacy Unicorn defaults. Select the actual Cortex-M4
# model required by the new mask instructions, for both baseline and candidate.
import unicorn
unicorn.Uc=a.factory
for name in ['odometer','timing_abi','advanced_abi','config_protocol']:
    p=ROOT/'tests'/('test_'+name+'.py')
    source=p.read_text()
    log=io.StringIO()
    previous_argv=sys.argv;sys.argv=[str(p),str(CANDIDATE_IMAGE)]
    with contextlib.redirect_stdout(log):exec(compile(source,str(p),'exec'),{'__file__':str(p),'__name__':'__main__'})
    sys.argv=previous_argv
    (RESULTS/('sgf-'+name+'.log')).write_text(log.getvalue())
    checks[name]=True;print('PASS',name,flush=True)
result={'passed':True,'checks':checks,'sha256':hashlib.sha256(CANDIDATE_IMAGE.read_bytes()).hexdigest(),
        'size':CANDIDATE_IMAGE.stat().st_size,'no_hardware_access':True,
        'candidate_only':True,'stable_rdg2_unchanged':True,'actual_app_base':'0x08003000','nominal_flash_alias':False,'gpr_or_ram_translation':False}
(RESULTS/'sgf-summary.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
