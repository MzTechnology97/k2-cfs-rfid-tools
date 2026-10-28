"""Current release inventory, documentation links and sanitized evidence checks."""
from pathlib import Path
from urllib.parse import urlsplit, unquote
import hashlib,json,re

ROOT = Path(__file__).resolve().parents[1]
manifest = json.loads((ROOT / 'firmware/cfg6-rdg2/manifest.json').read_text())
image = ROOT / 'firmware/cfg6-rdg2' / manifest['file']
assert list((ROOT / 'firmware').rglob('*.bin')) == [image]
assert not list((ROOT / 'firmware').glob('v3.*'))
assert hashlib.sha256(image.read_bytes()).hexdigest() == manifest['sha256']
assert len(image.read_bytes()) == manifest['size']
assert (ROOT / 'scripts/prepare_base.py').exists()
assert (ROOT / 'tests/run_offline.py').exists()
assert not (ROOT / '.github/workflows/cfs-v322-source-audit.yml').exists()
assert (ROOT / '.github/workflows/cfg6-rdg2.yml').exists()
broken = []
for file in [*ROOT.glob('*.md'), *(ROOT/'docs').rglob('*.md'),
             *(ROOT/'host').rglob('*.md'), *(ROOT/'firmware').rglob('*.md')]:
    for target in re.findall(r'!?\[[^\]]*\]\(([^\s)]+)\)', file.read_text()):
        if '://' in target or target.startswith(('#', 'mailto:', 'data:')):
            continue
        path = urlsplit(target).path
        if path and not (file.parent / unquote(path)).resolve().exists():
            broken.append((str(file.relative_to(ROOT)), target))
assert not broken, broken
evidence = json.loads((ROOT/'tests/fixtures/hardware-validation.json').read_text())
assert evidence['firmware_sha256'] == manifest['sha256']
for row in evidence['samples']:
    assert row['valid'] == 1 and row['type'] == 4
    expected = max(0, row['initial_percent'] - row['used_mm'] * 100 // row['total_mm'])
    assert row['table_percent'] == expected
assert evidence['samples'][-1]['table_percent'] == 34
assert all(value == 0 for key,value in evidence['last_session_link_deltas'].items()
           if key not in ('tx_frames', 'rx_frames'))
print(json.dumps({'passed':True,'only_current_installable_image':True,
                  'relative_document_links_valid':True,'hardware_evidence_matches_artifact':True}))
