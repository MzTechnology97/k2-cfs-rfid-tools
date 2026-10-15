#!/usr/bin/env python3
"""Fail-closed ADC motor-current provenance contract for saved CFS firmware.

Combines only authenticated *source-analysis* results. An ADC0_RDATA
helper is code evidence, NOT evidence of a current sensor conversion.
Unknown conversion sequence, callers, motor assignment, scaling or
electrical validity always forbids motor-stopped / v3.23 flash claims.

No device IO, firmware binary modification, or ADC RDATA reads.
"""
from __future__ import annotations
import argparse,json
from pathlib import Path
from flash_ram_phase2_audit import pinned
from cfs_adc_bounded_register_dataflow import analyze as dataflow
from cfs_adc_movw_movt_bounded_reachability import inspect as movable
from cfs_app_real_link_base_audit import audited

CURRENTS={
 "M1":{"pad":"PC5","possible_channel":15},
 "M2":{"pad":"PC0","possible_channel":10},
 "M3":{"pad":"PA1","possible_channel":1},
 "M4":{"pad":"PA0","possible_channel":0},
}

def examine(image:bytes)->dict:
    audited(image)
    d=dataflow(image)
    m=movable(image)
    # Report independent results without assuming any unverified
    # cross-function reachability. A positive source candidate cannot
    # turn a GPIO pad into an authenticated ADC measurement.
    return {
      "ADC_register_dataflow_candidates":d,
      "ADC_bounded_MOVW_MOVT_candidates":m["ADC_MOVW_MOVT_bounded_candidates"],
      "motor_current_pad_hardware_candidates":CURRENTS,
      "original_ADC_current_channel_sequence_for_M1_M4_proven":False,
      "original_motor_task_consumes_ADC_sample_proven":False,
      "current_sample_units_offset_gain_calibrated":False,
      "EOC_safe_nonintrusive_live_observation_proven":False,
      "driver_off_and_rotor_stopped_independently_proven":False,
      "current_zero_permits_firmware_write":False,
    }

def negative_cases():
    names=[
      "generic_ADC0_RDATA_helper_present_but_no_motor_caller",
      "ADC_channel_pad_possible_but_not_selected",
      "ADC_RDATA_sample_zero_but_motor_driver_enabled",
      "ADC_result_EOC_flag_may_change_on_second_read",
      "brushed_motor_stalled_and_no_BLDC_FG_pulses",
      "ADC_sample_stale_or_post_reset",
      "ADC_current_sensor_open_wire_reads_zero",
      "ADC_RDATA_sample_nonzero_without_motor_attribution",
      "ADC_channel_rank_sequence_ambiguous",
      "GPIO_motor_start_ISR_not_covered",
    ]
    result=[{"scenario":name,
             "motor_current_telemetry_authenticated":False,
             "MCU_SET_RESET_allowed":False,
             "flash_extended_v323_allowed":False} for name in names]
    assert len(result)==10
    return result

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v313",type=Path,required=True)
    p.add_argument("--v322",type=Path,required=True)
    p.add_argument("--json-out",type=Path)
    a=p.parse_args()
    old=examine(pinned(a.v313,"intermediate_v313"))
    new=examine(pinned(a.v322,"running_v322"))
    d=new["ADC_register_dataflow_candidates"]
    # Existing dataflow scanner independently enforces genuine
    # saved Thumb opcode content for its original ADC0_RDATA path.
    result={
       "saved_v313":old,
       "saved_v322":new,
       "same_motor_channel_evidence_across_versions":(
          old["motor_current_pad_hardware_candidates"]==
          new["motor_current_pad_hardware_candidates"]),
       "same_bounded_MOVW_MOVT_ADC_matches_across_versions":(
          old["ADC_bounded_MOVW_MOVT_candidates"]==
          new["ADC_bounded_MOVW_MOVT_candidates"]),
       "synthetic_negative_cases":negative_cases(),
       "physical_motor_feedback_authenticated":False,
       "installed_CFS_or_CM5_access":False,
       "safe_to_read_live_ADC_RDATA":False,
       "v323_release_gate_passed":False,
    }
    out=json.dumps(result,indent=2)+"\n"
    if a.json_out:a.json_out.write_text(out)
    print(out,end="")

if __name__=="__main__":main()
