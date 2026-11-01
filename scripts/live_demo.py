#!/usr/bin/env python3
"""
Wrapper for root live_demo.py so `python scripts/live_demo.py` also works identically.
"""
import os
import runpy
import sys

root_script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "live_demo.py"))
sys.path.insert(0, os.path.dirname(root_script))
runpy.run_path(root_script, run_name="__main__")
