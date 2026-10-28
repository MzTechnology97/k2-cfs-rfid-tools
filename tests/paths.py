"""Paths for the single maintained firmware; no machine-specific directories."""
from pathlib import Path
import os
ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / 'work/build'
RESULTS = ROOT / 'work/test-results'
RESULTS.mkdir(parents=True, exist_ok=True)
BASE_IMAGE = ROOT / 'work/base-pinned.bin'
CURRENT_IMAGE = ROOT / 'firmware/cfg6-rdg2/cfs0_050_G32-cfs0_000_153-K2OH-CFG6-RDG2.bin'
CANDIDATE_IMAGE = BUILD / 'candidate.bin'
HOST_MODULE = ROOT / 'host/kalico/box_rfid_diag.py'
KALICO = Path(os.environ.get('CFS_KALICO_ROOT', str(ROOT / 'work/kalico')))
KALICO_COMMIT = '1d7673da14a4860aa188e9b0ef563c5d97d80428'
