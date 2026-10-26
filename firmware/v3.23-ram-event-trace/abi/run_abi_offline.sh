#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build
arm-none-eabi-gcc -c -mcpu=cortex-m4 -mthumb -ffreestanding -nostdlib \
  motor_hook_abi_prototype.S -o build/motor_hook_abi_prototype.o
arm-none-eabi-ld -T motor_hook_abi_prototype.ld \
  -o build/motor_hook_abi_prototype.elf build/motor_hook_abi_prototype.o
arm-none-eabi-objcopy -O binary build/motor_hook_abi_prototype.elf \
  build/motor_hook_abi_prototype.bin
arm-none-eabi-gcc -c -mcpu=cortex-m4 -mthumb -ffreestanding -nostdlib \
  motor_hook_redirect.S -o build/motor_hook_redirect.o
arm-none-eabi-ld -T motor_hook_redirect.ld \
  -o build/motor_hook_redirect.elf build/motor_hook_redirect.o
arm-none-eabi-objcopy -O binary build/motor_hook_redirect.elf \
  build/motor_hook_redirect.bin
python3 emulate_hook_abi.py
echo "No deployable CFS firmware was built."
