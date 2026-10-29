"""Explicit test coordinates for the actual CFS application load address.

Sources/build symbols still name the earlier analysis coordinates. Convert only
attested code/Flash addresses and ELF symbol dictionaries at fixture boundaries.
Never call these helpers on CPU registers, RAM words, float bits or RFID data.
"""
NOMINAL_BASE=0x08010000
ACTUAL_BASE=0x08003000
CODE_BIAS=NOMINAL_BASE-ACTUAL_BASE
RETURN=0x0807E001  # Isolated return sentinel, outside every candidate image.

def code(nominal):
    assert isinstance(nominal,int) and NOMINAL_BASE<=nominal<0x08040000,hex(nominal)
    return nominal-CODE_BIAS  # Preserve the Thumb bit, if present.

def physical_symbols(symbols):
    """Rebase only named ELF Flash symbols; retain SRAM and absolute constants."""
    return {name:code(value) if NOMINAL_BASE<=value<0x08040000 else value
            for name,value in symbols.items()}
