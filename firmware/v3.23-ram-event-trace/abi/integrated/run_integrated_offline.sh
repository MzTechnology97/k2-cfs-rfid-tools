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
echo "ONLY isolated emulator binaries, NO flashable CFS firmware image."
