"""Validate the current CFS APP container, not the physical bootloader."""
import hashlib,json,struct
from paths import CURRENT_IMAGE, CANDIDATE_IMAGE, BUILD, RESULTS
SHA256 = '7d611c5845d3c248cf55f57972fdc7fab1761d0e281bcbf70030ac97e458023f'
def inspect(path):
    data = path.read_bytes()
    assert len(data) == 179976 and hashlib.sha256(data).hexdigest() == SHA256
    crc, size = struct.unpack_from('<HI', data, 0x20c)
    assert size == len(data) and data[0x200:0x20c] == b'cfs0_000_153'
    check = bytearray(data); check[0x20c:0x212] = bytes(6); value = 0
    for byte in check:
        value ^= byte << 8
        for _ in range(8):
            value = (((value << 1) ^ 0x8005) & 65535) if value & 32768 else ((value << 1) & 65535)
    assert value == crc
    sp, reset = struct.unpack_from('<II', data)
    assert sp == 0x20006ee8 and reset & 1
    assert 0x08003000 <= (reset & ~1) < 0x08003000 + len(data)
    assert 0x08003000 + len(data) < 0x0807f800
    return {'sha256': SHA256, 'size': len(data), 'crc16': hex(crc),
            'physical_end_exclusive': hex(0x08003000 + len(data)),
            'nominal_end_exclusive': hex(0x08010000 + len(data))}
if __name__ == '__main__':
    assert CURRENT_IMAGE.read_bytes() == CANDIDATE_IMAGE.read_bytes()
    result = {'passed': True, 'container': inspect(CURRENT_IMAGE)}
    (RESULTS / 'container.json').write_text(json.dumps(result))
    print(json.dumps(result))
