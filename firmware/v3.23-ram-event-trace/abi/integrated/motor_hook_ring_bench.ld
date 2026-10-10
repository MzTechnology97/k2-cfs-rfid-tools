SECTIONS {
  . = 0x08050000;
  .text : { *(.text.hook) *(.text) *(.text.*) }
  .rodata : { *(.rodata) *(.rodata.*) }
}