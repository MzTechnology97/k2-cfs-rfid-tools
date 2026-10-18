#!/usr/bin/env python3
"""Offline safety contract for proposed CFS motor-current telemetry.

An independent live read of GD32 ADC_RDATA can clear EOC. Never schedule
that read just because the ROM contains a generic ADC result helper.
This module is a source-only non-invasive policy regression; it adds NO
on-device instrumentation, motor-state authority or firmware image.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path
from flash_ram_phase2_audit import pinned
from cfs_gpio_d_adc0_helper_reachability_audit import inspect as inspect_helpers
from cfs_adc_bounded_register_dataflow import analyze as inspect_adc

def proposed_read_allowed(*, kind, adc_owner_known, source_verified,
                          freshness_proven, conversion_consumer_synchronized,
                          motor_coverage_proven, live_read=False):
    if kind in ("ADC_RDATA", "ADC_IDATA", "ADC_STAT", "GPIO_write", "ADC_trigger"):
        return False, "peripheral_side_effect_or_producer_interference"
    if kind not in ("preexisting_RAM_shadow", "hardware_telemetry"):
        return False, "unknown_source"
    if not (adc_owner_known and source_verified and freshness_proven
            and conversion_consumer_synchronized and motor_coverage_proven):
        return False, "unverified_signal_semantics_or_ownership"
    if live_read:
        return False, "live_collection_requires_separate_review"
    return True, "synthetic_plan_only_not_motor_stop"

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--v313",required=True,type=Path)
    a.add_argument("--v322",required=True,type=Path)
    a.add_argument("--json-out",type=Path)
    args=a.parse_args()
    old=pinned(args.v313,"intermediate_v313")
    new=pinned(args.v322,"running_v322")
    for image in (old,new):
        helpers=inspect_helpers(image)
        adc=inspect_adc(image)
        if helpers["adc0_effective_read_addr_if_called"]!="0x4001244c":
            raise ValueError("original ADC0_RDATA source address changed")
        if adc["original_ADC0_RDATA_source_instruction_locally_verified"]!="0x8022bc0":
            raise ValueError("original ADC0 data-reader instruction changed")
        if not helpers["ADC0_direct_read_helper_is_not_proven_to_be_invoked"]:
            raise ValueError("previous ADC helper reachability status changed")
    scenarios=[
       ("direct_RDATA",dict(kind="ADC_RDATA")),
       ("direct_IDATA",dict(kind="ADC_IDATA")),
       ("ADC_STAT",dict(kind="ADC_STAT")),
       ("unknown_probe",dict(kind="unknown")),
       ("shadow_without_owner",dict(kind="preexisting_RAM_shadow")),
       ("shadow_without_freshness",dict(kind="preexisting_RAM_shadow",adc_owner_known=True,source_verified=True)),
       ("shadow_without_coverage",dict(kind="preexisting_RAM_shadow",adc_owner_known=True,source_verified=True,freshness_proven=True,conversion_consumer_synchronized=True)),
       ("shadow_all_claims_but_live",dict(kind="preexisting_RAM_shadow",adc_owner_known=True,source_verified=True,freshness_proven=True,conversion_consumer_synchronized=True,motor_coverage_proven=True,live_read=True)),
       ("shadow_synthetic_qualified",dict(kind="preexisting_RAM_shadow",adc_owner_known=True,source_verified=True,freshness_proven=True,conversion_consumer_synchronized=True,motor_coverage_proven=True)),
    ]
    defaults=dict(adc_owner_known=False,source_verified=False,freshness_proven=False,conversion_consumer_synchronized=False,motor_coverage_proven=False,live_read=False)
    checks=[]
    for name,kw in scenarios:
        ok,why=proposed_read_allowed(**(defaults|kw))
        if ok != (name=="shadow_synthetic_qualified"):
            raise AssertionError("unsafe hypothetical ADC observation approved: "+name)
        checks.append(dict(name=name,synthetic_plan_only=ok,reason=why,
                           permission_for_actual_MCU_read=False,
                           physical_motor_stopped_proven=False))
    result=dict(original_v313_v322_ADC_reader_verified=True,
                synthetic_cases=checks,synthetic_cases_passed=len(checks),
                real_ADC_conversion_owner_authenticated=False,
                actual_MCU_ADC_RDATA_probed=False,
                motor_current_feedback_and_calibration_proven=False,
                v323_flash_or_MCU_write_permitted=False)
    output=json.dumps(result,indent=2)+"\n"
    if args.json_out:args.json_out.write_text(output)
    print(output,end="")
if __name__=="__main__":main()
