#!/usr/bin/env python3
"""Rebuild and validate only the maintained RDG2 firmware, never a device."""
from pathlib import Path
import argparse,hashlib,json,os,subprocess,sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from paths import BASE_IMAGE, CURRENT_IMAGE, CANDIDATE_IMAGE, BUILD, RESULTS

def run(argv, name, python=None, env=None):
    result = subprocess.run([python or sys.executable, *map(str, argv)],
                            cwd=ROOT, capture_output=True, text=True, env=env)
    (RESULTS / (name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        print((result.stdout + result.stderr)[-6000:])
        raise SystemExit('FAILED: ' + name)
    print('PASS:', name, flush=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--kalico', type=Path, help='Optional pinned Kalico checkout for host integration tests')
    ap.add_argument('--host-python', help='Optional Python interpreter with pytest for host tests')
    args = ap.parse_args()
    run(['scripts/prepare_base.py'], 'base-recovery')
    run(['firmware/cfg6-rdg2/build.py', '--base', BASE_IMAGE,
         '--out', CANDIDATE_IMAGE, '--build-dir', BUILD], 'rebuild')
    digest = hashlib.sha256(CANDIDATE_IMAGE.read_bytes()).hexdigest()
    assert digest == '7d611c5845d3c248cf55f57972fdc7fab1761d0e281bcbf70030ac97e458023f'
    assert CURRENT_IMAGE.read_bytes() == CANDIDATE_IMAGE.read_bytes()
    tests = [
        ('release-layout', ['tests/test_release_layout.py']),
        ('container', ['tests/test_container.py']),
        ('odometer', ['tests/test_odometer.py']),
        ('timing-abi', ['tests/test_timing_abi.py']),
        ('advanced-abi', ['tests/test_advanced_abi.py']),
        ('config-protocol', ['tests/test_config_protocol.py', CANDIDATE_IMAGE]),
        ('accounting', ['tests/test_accounting.py', '--out', RESULTS / 'accounting.json']),
        ('boundaries', ['tests/test_boundaries.py']),
        ('cmd03-paths', ['tests/test_cmd03.py']),
        ('snapshot', ['tests/test_snapshot.py']),
    ]
    for name, argv in tests:
        run(argv, name)
    if args.kalico:
        env = dict(os.environ, CFS_KALICO_ROOT=str(args.kalico.resolve()),
                   PYTHONDONTWRITEBYTECODE='1', PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
        run(['tests/test_host_reader.py'], 'host-reader', args.host_python, env)
        run(['tests/run_host_regressions.py'], 'host-legacy', args.host_python, env)
    result = {'passed': True, 'sha256': digest, 'firmware_groups': len(tests),
              'host_integration_included': args.kalico is not None,
              'no_hardware_access': True}
    (RESULTS / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))

if __name__ == '__main__':main()
