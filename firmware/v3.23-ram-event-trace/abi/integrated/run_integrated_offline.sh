#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build
arm-none-eabi-gcc -c -mcpu=cortex-m4 -mthumb -ffreestanding -nostdlib \
  -Wall -Wextra -Werror motor_hook_ring_bench.S -o build/motor_hook_ring_bench.o
arm-none-eabi-gcc -c -mcpu=cortex-m4 -mthumb -Os -ffreestanding -nostdlib \
  -Wall -Wextra -Werror -I ../.. motor_hook_ring_logger.c -o build/motor_hook_ring_logger.o
arm-none-eabi-gcc -c -mcpu=cortex-m4 -mthumb -Os -ffreestanding -nostdlib \
  -Wall -Wextra -Werror -I ../.. ../../trace_ring.c -o build/trace_ring-Osize.o
arm-none-eabi-gcc -nostdlib -mcpu=cortex-m4 -mthumb \
  -Wl,-T,motor_hook_ring_bench.ld \
  build/motor_hook_ring_bench.o build/motor_hook_ring_logger.o \
  build/trace_ring-Osize.o -lgcc -o build/motor_hook_ring_bench.elf
arm-none-eabi-objcopy -O binary build/motor_hook_ring_bench.elf \
  build/motor_hook_ring_bench.bin
arm-none-eabi-gcc -c -mcpu=cortex-m4 -mthumb -ffreestanding -nostdlib \
  ../motor_hook_redirect.S -o build/motor_hook_redirect.o
arm-none-eabi-ld -T ../motor_hook_redirect.ld \
  -o build/motor_hook_redirect.elf build/motor_hook_redirect.o
arm-none-eabi-objcopy -O binary build/motor_hook_redirect.elf \
  build/motor_hook_redirect.bin
arm-none-eabi-size build/motor_hook_ring_bench.elf
python3 emulate_ring_hook.py
python3 emulate_ring_stress.py
# Exact offline code-only footprint of logger + buffer + frozen GET serializer.
# This is NOT a complete firmware: missing serial dispatch, tick, and real hooks.
arm-none-eabi-gcc -c -mcpu=cortex-m4 -mthumb -Os -ffreestanding -nostdlib \
  -Wall -Wextra -Werror -I ../.. ../../trace_readback.c \
  -o build/trace_readback.o
arm-none-eabi-gcc -nostdlib -mcpu=cortex-m4 -mthumb \
  -Wl,-T,motor_hook_ring_bench.ld \
  build/motor_hook_ring_bench.o build/motor_hook_ring_logger.o \
  build/trace_ring-Osize.o build/trace_readback.o -lgcc \
  -o build/motor_hook_ring_readback.elf
arm-none-eabi-size build/motor_hook_ring_readback.elf
python3 - <<'PY'
import subprocess
def text_bytes(p):
    result = subprocess.check_output(["arm-none-eabi-size", p], text=True)
    return int(result.strip().splitlines()[-1].split()[0])
core = text_bytes("build/motor_hook_ring_bench.elf")
with_readback = text_bytes("build/motor_hook_ring_readback.elf")
# Current v3.22 tested end is 0x803B7DC; conservative cap 0x803B800.
headroom = 0x0803B800 - 0x0803B7DC
print("Instrumented motor hook and RAM ring:", core, "bytes")
print("Including frozen read-only 0x57 response serializer:", with_readback, "bytes")
print("Code beyond empirical headroom BEFORE serial protocol/clock:", with_readback-headroom)
assert with_readback > core > headroom
PY
python3 emulate_ring_wrap.py
echo "ONLY isolated emulator binaries, NO flashable CFS firmware image."
