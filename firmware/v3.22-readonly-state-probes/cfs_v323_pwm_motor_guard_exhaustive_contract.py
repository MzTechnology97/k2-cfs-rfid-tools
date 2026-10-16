#!/usr/bin/env python3
"""Exhaustive fail-closed motor interlock contract: no firmware writes.

Enumerate every boolean combination of controller observations versus
the *safety* conditions. The timer PWM readback is not motor-stop proof.
This is a policy model, not MCU implementation or a release gate.
"""
from __future__ import annotations
import argparse, itertools, json
from pathlib import Path
from cfs_motor_busy_guard_contract import Feedback, Snapshot, candidate_interlock

def verify():
    rows=[]
    names=('box_idle','feeder_off','hub_off','buffer_off','fresh',
           'physical_feedback_verified','motion_lock','all_start_paths','epoch_stable',
           'timer_pwm_outputs_disabled')
    accepted=0
    for flags in itertools.product((False,True), repeat=len(names)):
        x=dict(zip(names,flags))
        sample=Snapshot(
            box_state=0 if x['box_idle'] else 1,
            feeder=Feedback.STOPPED if x['feeder_off'] else Feedback.ACTIVE,
            hub=Feedback.STOPPED if x['hub_off'] else Feedback.ACTIVE,
            buffer=Feedback.STOPPED if x['buffer_off'] else Feedback.ACTIVE,
            update_epoch=17,
            verified_feedback=x['physical_feedback_verified'],
            age_ms=1 if x['fresh'] else 99,
            motion_lock_held=x['motion_lock'],
            covers_all_start_paths=x['all_start_paths'])
        allowed,reason=candidate_interlock(sample,17 if x['epoch_stable'] else 18)
        # Exhaustive safety-policy property: timer output bits, whether
        # all clear or not, MUST NOT influence a motor stop decision.
        controls=all(x[k] for k in names if k!='timer_pwm_outputs_disabled')
        if allowed!=controls:raise AssertionError(('guard policy drift',x,reason))
        if allowed:accepted+=1
        rows.append((x['timer_pwm_outputs_disabled'],allowed,reason))
    if len(rows)!=1024 or accepted!=2:
        raise AssertionError('state-space size or policy boundaries changed')
    paired={}
    for disabled,allowed,reason in rows:
        paired.setdefault((allowed,reason),set()).add(disabled)
    if any(values!={False,True} for values in paired.values()):
        raise AssertionError('PWM bit pattern inadvertently changes motor guard decision')
    # The decisive negative: even zero PWM enables together with BOX IDLE
    # cannot authorize writes in the currently implemented CFS. Unverified
    # physical feedback and lack of MCU shared lock are blockers.
    observed=Snapshot(0,Feedback.UNKNOWN,Feedback.UNKNOWN,Feedback.UNKNOWN,
                      17,False,1,False,False)
    ok,why=candidate_interlock(observed,17)
    if ok:raise AssertionError('unverified physical motor state got authorized')
    return {
        'enumerated_model_states':1024,
        'synthetic_only_accepted_cases':accepted,
        'paired_PWM_off_on_contract_equal':True,
        'timer_enable_registers_sufficient_as_stop_evidence':False,
        'actual_CFS_sensor_identity_authenticated':False,
        'atomic_RTThread_ISR_motor_lock_in_original_MCU':False,
        'write_SET_RESET_unblocked_in_first_test_build':False,
        'existing_v323_config_guard_remains_fail_closed':True,
        'real_flash_or_motor_io':False,
        'Kalico_source_edited':False,
        'unqualified_hardware_snapshot_denied':why,
    }

def main():
    a=argparse.ArgumentParser()
    a.add_argument('--json-out',type=Path)
    opt=a.parse_args()
    result=verify()
    out=json.dumps(result,indent=2)+'\n'
    if opt.json_out:opt.json_out.write_text(out)
    print(out,end='')
if __name__=='__main__':main()
