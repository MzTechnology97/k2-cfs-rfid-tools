"""Run paired Kalico regression tests against the bundled reader, in-process injection only."""
import importlib.util,json,os,subprocess,sys
from paths import KALICO, KALICO_COMMIT, HOST_MODULE, RESULTS
import pytest
actual = subprocess.check_output(['git', '-C', str(KALICO), 'rev-parse', 'HEAD'], text=True).strip()
assert actual == KALICO_COMMIT, 'Use the documented pinned Kalico commit for this regression suite'
sys.path.insert(0, str(KALICO / 'klippy'))
import extras
spec = importlib.util.spec_from_file_location('extras.box_rfid_diag', HOST_MODULE)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
extras.box_rfid_diag = module
code = pytest.main(['-q', '--noconftest', '-p', 'no:cacheprovider',
    str(KALICO / 'test/test_box_rfid_diag_type4.py'),
    str(KALICO / 'test/test_box_rfid_bambu_stock_wait.py'),
    str(KALICO / 'test/test_box_rfid_fallback_registry.py')])
(RESULTS / 'host-legacy.json').write_text(json.dumps({'passed': code == 0,
    'kalico_commit': actual, 'pytest_exit_code': int(code), 'no_hardware_access': True}))
raise SystemExit(code)
