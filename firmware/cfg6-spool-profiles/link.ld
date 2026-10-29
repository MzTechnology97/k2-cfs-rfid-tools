SECTIONS { . = 0x0803AE38; .text : { *(.text.handler) *(.text*) *(.rodata*) . = ALIGN(4); __image_end__ = .; } /DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) *(.note*) } }
