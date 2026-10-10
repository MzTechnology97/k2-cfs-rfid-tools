#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build
gcc -std=c11 -O2 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer trace_ring.c test_trace_ring.c -o build/test_trace_ring
./build/test_trace_ring
arm-none-eabi-gcc -std=c11 -O2 -Wall -Wextra -Werror -mcpu=cortex-m3 -mthumb -ffreestanding -nostdlib -c trace_ring.c -o build/trace_ring-arm.o
arm-none-eabi-size build/trace_ring-arm.o
arm-none-eabi-gcc -std=c11 -Os -Wall -Wextra -Werror -mcpu=cortex-m3 -mthumb -ffreestanding -nostdlib -c trace_ring.c -o build/trace_ring-arm-size.o
arm-none-eabi-size build/trace_ring-arm-size.o
# Compare only the text footprint; this model is not integrated in a firmware.
python3 - <<'PY'
import subprocess
def text_size(path):
    p = subprocess.check_output(["arm-none-eabi-size", path], text=True)
    return int(p.strip().splitlines()[-1].split()[0])
standard = text_size("build/trace_ring-arm.o")
compact = text_size("build/trace_ring-arm-size.o")
print("RAM ring ARM .text:", standard, "bytes -O2;", compact, "bytes -Os")
assert compact <= standard and compact > 0
PY
echo "NO firmware BIN generated or installed."
if [ "$#" -eq 1 ]; then python3 preflight_v323.py --firmware "$1"; fi
