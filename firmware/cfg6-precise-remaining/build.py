#!/usr/bin/env python3
# Build only the separate R4 precision candidate; R3 remains reproducible.
from pathlib import Path
import runpy
import sys
builder = Path(__file__).resolve().parents[1] / 'cfg6-spool-profiles/build.py'
sys.argv = [str(builder), *sys.argv[1:], '--precise-remaining']
runpy.run_path(str(builder), run_name='__main__')
