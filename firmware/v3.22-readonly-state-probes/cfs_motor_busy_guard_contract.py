#!/usr/bin/env python3
"""Fail-closed v3.23 MCU write-interlock *SPECIFICATION*, not production code.

Read only SHA-pinned saved v3.22 handler assembly; prove the present
SET and RESET commands each use BOX_OPER_STATE+2 alone for their early
busy decision. Test a proposed *future* interlock with independent
motion feedback and a shared dispatch epoch, without claiming actual
CFS motor feedback has been discovered.

No firmware build, serial, motion, CFS, Kalico writes, flash or patches.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Feedback(Enum):
    STOPPED = "stopped"
    ACTIVE = "active"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Snapshot:
    box_state: int
    feeder: Feedback
    hub: Feedback
    buffer: Feedback
    update_epoch: int
    verified_feedback: bool
    age_ms: int
    motion_lock_held: bool
    covers_all_start_paths: bool


def candidate_interlock(s: Snapshot, commit_epoch: int) -> tuple[bool, str]:
    """Simulation only: a real MCU implementation is NOT present or approved."""
    if not s.motion_lock_held or not s.covers_all_start_paths:
        return False, "unsynchronized_motion_start"
    if not s.verified_feedback:
        return False, "feedback_semantics_unproven"
    if s.age_ms < 0 or s.age_ms > 10:
        return False, "feedback_stale"
    if s.box_state != 0:
        return False, "box_state_not_idle"
    if any(f is Feedback.UNKNOWN for f in (s.feeder, s.hub, s.buffer)):
        return False, "unknown_motor_feedback"
    if any(f is Feedback.ACTIVE for f in (s.feeder, s.hub, s.buffer)):
        return False, "motor_active"
    if s.update_epoch != commit_epoch:
        return False, "motion_started_between_check_and_commit"
    return True, "synthetic_idle_only_not_hardware_proof"


def current_handler_guard(asm: str) -> dict:
    # Strip ARM assembly comments, preserve real labels/instruction order.
    code = "\n".join(line.split("@", 1)[0].strip() for line in asm.splitlines())
    matches = {}
    for label in ("op_config_v2_set", "op_config_v2_reset"):
        m = re.search(rf"(?m)^{label}:\s*$", code)
        if not m:
            raise ValueError(f"stock handler {label} not found")
        nxt = re.search(r"(?m)^[a-zA-Z_][a-zA-Z_0-9]*:\s*$", code[m.end():])
        body = code[m.end(): m.end()+nxt.start()] if nxt else code[m.end():]
        instructions = [line for line in body.splitlines() if line and not line.startswith(".")]
        sequence = [
            "ldr r0, box_operating_state_ptr",
            "ldrb r0, [r0, #2]",
            "cmp r0, #0",
            "bne.w status_busy",
        ]
        compact = [re.sub(r"\s+", " ", line).strip() for line in instructions]
        pos = 0
        for ins in sequence:
            try:
                pos = compact.index(ins, pos) + 1
            except ValueError as e:
                raise ValueError(f"{label}: BOX_STATE branch changed; manual review required") from e
        precommit = "\n".join(compact)
        if label.endswith("_set"):
            mutation = "strh r7, [r5, r3]"
        else:
            mutation = "str r0, [r5, #4]"
        if mutation not in precommit:
            raise ValueError(f"{label}: expected sidecar mutation not found")
        if precommit.index("ldr r0, box_operating_state_ptr") > precommit.index(mutation):
            raise ValueError(f"{label}: busy check after first write")
        matches[label] = {
            "box_state_only_guard_sequence_found": True,
            "first_sidecar_write": mutation,
            "independent_motor_feedback_guard_proven": False,
            "MCU_atomicity_proven": False,
        }
    if code.count("box_operating_state_ptr") < 3:
        raise ValueError("global BOX_STATE literal unexpectedly absent")
    return matches


def synthetic_tests() -> list[dict]:
    ok = Snapshot(0, Feedback.STOPPED, Feedback.STOPPED, Feedback.STOPPED,
                  100, True, 1, True, True)
    cases = [
        ("synthetic_idle", ok, 100, True, "synthetic_idle_only_not_hardware_proof"),
        ("real_observed_box_idle_during_feeding",
         Snapshot(0, Feedback.ACTIVE, Feedback.STOPPED, Feedback.STOPPED, 100,True,1,True,True),
         100,False,"motor_active"),
        ("box_busy_with_stopped_motors",
         Snapshot(2,Feedback.STOPPED,Feedback.STOPPED,Feedback.STOPPED,100,True,1,True,True),
         100,False,"box_state_not_idle"),
        ("unknown_hub_motor",
         Snapshot(0,Feedback.STOPPED,Feedback.UNKNOWN,Feedback.STOPPED,100,True,1,True,True),
         100,False,"unknown_motor_feedback"),
        ("sensor_absent",
         Snapshot(0,Feedback.STOPPED,Feedback.STOPPED,Feedback.STOPPED,100,False,1,True,True),
         100,False,"feedback_semantics_unproven"),
        ("stale_sensor",
         Snapshot(0,Feedback.STOPPED,Feedback.STOPPED,Feedback.STOPPED,100,True,30,True,True),
         100,False,"feedback_stale"),
        ("motion_start_race",
         ok,101,False,"motion_started_between_check_and_commit"),
        ("missing_dispatch_lock",
         Snapshot(0,Feedback.STOPPED,Feedback.STOPPED,Feedback.STOPPED,100,True,1,False,True),
         100,False,"unsynchronized_motion_start"),
        ("uncovered_ISR_start_path",
         Snapshot(0,Feedback.STOPPED,Feedback.STOPPED,Feedback.STOPPED,100,True,1,True,False),
         100,False,"unsynchronized_motion_start"),
        ("RFID_no_sensor_assignment",
         Snapshot(0,Feedback.UNKNOWN,Feedback.UNKNOWN,Feedback.UNKNOWN,100,False,1,False,False),
         100,False,"unsynchronized_motion_start"),
    ]
    out=[]
    for name, s, epoch, want, reason in cases:
        got, why=candidate_interlock(s,epoch)
        if (got,why)!=(want,reason):
            raise AssertionError(f"{name} changed expected policy: {got}, {why}")
        out.append({"case":name,"candidate_accepts_in_simulation":got,
                    "reason":why, "real_MCU_WRITE_authorized":False})
    # The real v3.22 and future v3.23 must never be authorized by
    # the synthetic success case.
    assert sum(x["candidate_accepts_in_simulation"] for x in out)==1
    return out


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--handler",type=Path,required=True)
    ap.add_argument("--json-out",type=Path)
    args=ap.parse_args()
    source=args.handler.read_text()
    current=current_handler_guard(source)
    cases=synthetic_tests()
    result={
      "scope":"offline v3.22 handler source audit and abstract future motor-busy interlock",
      "source_sha256":hashlib.sha256(source.encode()).hexdigest(),
      "current_handler_paths":current,
      "tests":cases,
      "synthetic_tests_passed":len(cases),
      "real_feeder_hub_buffer_feedback_source_authenticated":False,
      "motor_start_and_ISR_coverage_proven":False,
      "atomic_write_commit_implemented_in_MCU":False,
      "host_Kalico_movement_lock_sufficient_by_itself":False,
      "current_v322_busy_guard_uses_only_box_state":True,
      "release_gate_9_independent_motor_stop_PROVEN":False,
      "real_v323_flash_or_motor_writes_authorized":False,
      "performed_CFS_or_CM5_IO":False,
    }
    out=json.dumps(result,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(out)
    print(out,end="")

if __name__=="__main__":main()
