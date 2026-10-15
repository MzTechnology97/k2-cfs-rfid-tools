#!/usr/bin/env python3
"""CFS motor evidence matrix and future READ-ONLY observation manifest.

Cross-verifies manufacturer v3.13/v3.22 original ROM and decoded SRAM
for five TIMER PWM *outputs*, PE11 GPIO event producer, and sampled
motor activity RAM. Builds a diagnostic manifest of ONLY potential
read-only register/counter observations; does NOT read any MCU.

The safety classifier distinguishes positive evidence of ACTIVITY from
UNKNOWN. It never emits motor-STATIONARY or write permission because
hardware sensor identity, motor/driver coverage and interrupt
synchronization remain unverified. Synthetic input is not live data.

Neither Klipper/Kalico, CM5 nor CFS is accessed or changed.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, replace
from pathlib import Path

from flash_ram_phase2_audit import pinned
from cfs_pwm_timer_channel_register_provenance import inspect as pwm_channels
from cfs_pwm_timer_afio_remap_provenance import verify as afio_remap
from cfs_motor_pulse_irq_provenance import analyze as pulse_irq

# All values below are original firmware-mapped peripheral locations,
# NOT values measured from any real GD32 or CFS. No MMIO is executed.
T0 = 0x40012C00
T3 = 0x40000800
AFIO_PCF0 = 0x40010004
COUNTER = 0x20004990
LAST_COUNTER = 0x20004994
METRIC = 0x2000498C
COUNTDOWN = 0x2000499C
MASK32 = 0xffffffff


def manifest(image: bytes) -> dict:
    a = pwm_channels(image)
    b = afio_remap(image)
    c = pulse_irq(image)
    pins = a["full_oem_timer_channel_register_map"]
    if len(pins) != 5:
        raise ValueError("original five PWM channel list changed")
    expected = [
        ("pwm1", "PE13", 0, 2, T0, 0x40012C3C, 0x100),
        ("pwm3", "PD12", 3, 0, T3, 0x40000834, 0x001),
        ("pwm4", "PD13", 3, 1, T3, 0x40000838, 0x010),
        ("pwm5", "PD15", 3, 3, T3, 0x40000840, 0x1000),
        ("pwm8", "PD14", 3, 2, T3, 0x4000083C, 0x100),
    ]
    mapping = []
    for item, (name, gpio, select, channel, base, compare, enable) in zip(pins, expected):
        got = (
            item["RTThread_device_name"],
            item["OEM_GPIO_AF_output"],
            item["original_timer_selector_from_plus_0x44"],
            item["original_channel_index_from_plus_0x50"],
            int(item["OEM_TIMER_peripheral_base"], 16),
            int(item["original_channel_compare_register"], 16),
            item["channel_output_enable_bit"],
        )
        if got != (name, gpio, select, channel, base, compare, enable):
            raise ValueError(f"OEM descriptor/TIMER register mismatch: {name}")
        if int(item["original_channel_output_enable_register"],16) != base+0x20:
            raise ValueError("original TIMER_CHCTL2 register offset changed")
        mapping.append({
            "device": name,
            "gpio_output": gpio,
            "timer": f"TIMER{select}",
            "channel": channel,
            "compare_register": hex(compare),
            "output_enable_register": hex(base+0x20),
            "output_enable_mask": hex(enable),
            "register_role": "command_output_only_not_rotor_feedback",
            "read_permission_on_actual_CFS": False,
        })
    if {x["device"] for x in mapping} != {"pwm1","pwm3","pwm4","pwm5","pwm8"}:
        raise ValueError("OEM PWM device identities differ")
    if c["resolved_interrupt_GPIO_pin"] != "PE11":
        raise ValueError("manufacturer logical pin 0x4B mapping changed")
    if (int(c["original_counter_RAM"],16), int(c["sampled_previous_counter_RAM"],16),
        int(c["sampled_difference_float_RAM"],16),
        int(c["software_activity_flag_RAM"],16)) != (COUNTER,LAST_COUNTER,METRIC,COUNTDOWN):
        raise ValueError("IRQ counter/sample RAM map changed")
    if b["AFIO_PCF0_physical_register"] != hex(AFIO_PCF0):
        raise ValueError("AFIO register provenance changed")
    if not (b["TIMER0_full_remap_requested_in_original_code"] and
            b["TIMER3_remap_requested_in_original_code"]):
        raise ValueError("OEM PWM remap request not fully covered")
    return {
        "saved_firmware_physical_APP_base":"0x08003000",
        "pwm_command_output_registers":mapping,
        "unique_timer_channel_pairs":len({(x["timer"],x["channel"]) for x in mapping}),
        "gpio_pulse_input":"PE11",
        "gpio_pulse_pin_id":"0x4b",
        "pulse_counter_RAM":hex(COUNTER),
        "previous_counter_RAM":hex(LAST_COUNTER),
        "sampled_float_RAM":hex(METRIC),
        "derived_software_countdown_RAM":hex(COUNTDOWN),
        "afio_remap_register":hex(AFIO_PCF0),
        "pwm_output_enabled_means_motor_physically_rotating":False,
        "zero_PWM_command_plus_zero_pulses_proves_rotor_stopped":False,
        "pulse_input_assigned_to_all_motors_proven":False,
        "complete_driver_and_ISR_coverage_proven":False,
        "read_only_diagnostic_manifest_not_a_live_sample":True,
        "actual_MMIO_or_RAM_read_performed":False,
        "write_permission_authorized":False,
    }


@dataclass(frozen=True)
class Synthetic:
    # All fields are hypothetical values; no hardware data has been read.
    t0_chctl2: int = 0
    t3_chctl2: int = 0
    pulse_before: int = 123
    pulse_after: int = 123
    observed_timestamp_age_ms: int = 1
    irq_enabled_verified: bool = True
    sensor_wiring_verified: bool = True
    counters_not_reset_during_window: bool = True
    sampling_epoch_before: int = 21
    sampling_epoch_after: int = 21
    box_idle: bool = True
    motor_driver_known_deenergized: bool = False
    every_motor_and_start_path_covered: bool = False


def classify(sample: Synthetic, mapping: dict) -> dict:
    if sample.observed_timestamp_age_ms < 0 or sample.observed_timestamp_age_ms > 10:
        reason = "stale_or_invalid_snapshot"
        active = []
        pulse_delta = None
    elif sample.sampling_epoch_before != sample.sampling_epoch_after:
        reason = "torn_snapshot_or_concurrent_motor_transition"
        active = []
        pulse_delta = None
    elif not sample.counters_not_reset_during_window:
        reason = "pulse_counter_reset_or_discontinuity"
        active = []
        pulse_delta = None
    elif not sample.irq_enabled_verified or not sample.sensor_wiring_verified:
        reason = "sensor_irq_or_wiring_unverified"
        active = []
        pulse_delta = None
    else:
        active = [
            p["device"] for p in mapping["pwm_command_output_registers"]
            if ((sample.t0_chctl2 if p["timer"]=="TIMER0" else sample.t3_chctl2)
                & int(p["output_enable_mask"],16))
        ]
        pulse_delta = (sample.pulse_after - sample.pulse_before) & MASK32
        if active:
            reason = "known_timer_pwm_output_enabled"
        elif pulse_delta != 0:
            reason = "recent_external_gpio_pulses"
        elif not sample.box_idle:
            reason = "software_box_state_not_idle"
        elif not sample.motor_driver_known_deenergized:
            reason = "driver_electrical_state_unverified"
        elif not sample.every_motor_and_start_path_covered:
            reason = "other_motor_or_ISR_paths_unverified"
        else:
            reason = "physical_standstill_and_atomic_commit_not_proven"
    return {
        "synthetic_evidence":True,
        "known_pwm_outputs_enabled":active,
        "modulo_uint32_gpio_pulse_delta":pulse_delta,
        "reason":reason,
        # Positive evidence of an ACTIVE *PWM output* or pulses is not
        # the same as proving shaft motion. All other states UNKNOWN.
        "motion_classification":"COMMAND_OR_PULSES_DETECTED" if reason in (
            "known_timer_pwm_output_enabled","recent_external_gpio_pulses"
        ) else "UNKNOWN",
        "physical_motor_STOPPED_proven":False,
        "MCU_SET_RESET_permission":False,
    }


def synthetic_contract(mapping: dict) -> list[dict]:
    base = Synthetic()
    cases = [
        ("zero_output_zero_pulse_unknown",base,"driver_electrical_state_unverified"),
        ("real_false_idle_feeding_no_pulses",replace(base,t0_chctl2=0x100),
         "known_timer_pwm_output_enabled"),
        ("all_ch0_commanded_but_stalled",replace(base,t3_chctl2=0x001),
         "known_timer_pwm_output_enabled"),
        ("all_ch1_commanded_but_stalled",replace(base,t3_chctl2=0x010),
         "known_timer_pwm_output_enabled"),
        ("all_ch2_commanded_but_stalled",replace(base,t3_chctl2=0x100),
         "known_timer_pwm_output_enabled"),
        ("all_ch3_commanded_but_stalled",replace(base,t3_chctl2=0x1000),
         "known_timer_pwm_output_enabled"),
        ("pulses_after_PWM_off",replace(base,pulse_after=127),
         "recent_external_gpio_pulses"),
        ("uint32_pulse_wrap",replace(base,pulse_before=0xfffffffe,pulse_after=1),
         "recent_external_gpio_pulses"),
        ("counter_reset_masking_activity",replace(base,pulse_after=0,
                                                 counters_not_reset_during_window=False),
         "pulse_counter_reset_or_discontinuity"),
        ("stale_snapshot",replace(base,observed_timestamp_age_ms=500),
         "stale_or_invalid_snapshot"),
        ("motor_start_between_samples",replace(base,sampling_epoch_after=22),
         "torn_snapshot_or_concurrent_motor_transition"),
        ("IRQ_not_authenticated",replace(base,irq_enabled_verified=False),
         "sensor_irq_or_wiring_unverified"),
        ("unknown_sensor_wiring",replace(base,sensor_wiring_verified=False),
         "sensor_irq_or_wiring_unverified"),
        ("box_reports_busy",replace(base,box_idle=False),
         "software_box_state_not_idle"),
        ("driver_off_but_missing_motors",replace(base,motor_driver_known_deenergized=True),
         "other_motor_or_ISR_paths_unverified"),
        ("all_hypothetically_quiet_still_unqualified",
         replace(base,motor_driver_known_deenergized=True,
                 every_motor_and_start_path_covered=True),
         "physical_standstill_and_atomic_commit_not_proven"),
    ]
    rows=[]
    for name,s,want in cases:
        got=classify(s,mapping)
        if got["reason"]!=want or got["MCU_SET_RESET_permission"] or got["physical_motor_STOPPED_proven"]:
            raise AssertionError(f"synthetic motor evidence classification changed at {name}")
        if name=="uint32_pulse_wrap" and got["modulo_uint32_gpio_pulse_delta"]!=3:
            raise AssertionError("uint32 wrap-aware pulse delta not tested")
        rows.append({"case":name,**got})
    if len(rows)!=16:
        raise AssertionError("safety case fixture count changed")
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--v313",required=True,type=Path)
    ap.add_argument("--v322",required=True,type=Path)
    ap.add_argument("--json-out",type=Path)
    a=ap.parse_args()
    old=manifest(pinned(a.v313,"intermediate_v313"))
    new=manifest(pinned(a.v322,"running_v322"))
    if old!=new:
        raise ValueError("OEM multi-signal provenance differs between pinned v3.13/v3.22")
    tests=synthetic_contract(new)
    result={
      "v313_equals_v322":True,
      "original_signal_manifest":new,
      "synthetic_safety_cases":tests,
      "safety_cases_executed":len(tests),
      "physical_motor_sensors_authenticated":False,
      "all_motor_driver_and_ISR_owners_recovered":False,
      "read_only_data_source_available_on_installed_CFS":False,
      "actual_device_registers_sampled":False,
      "MCU_motion_interlock_implemented":False,
      "safe_to_flash_extended_v323":False,
      "real_CFS_CM5_Kalico_interacted":False,
    }
    out=json.dumps(result,indent=2)+"\n"
    if a.json_out:
        a.json_out.write_text(out)
    print(out,end="")


if __name__=="__main__":
    main()
