#!/usr/bin/env python3
"""Тест REP в новом процессе"""
import subprocess
import sys

result = subprocess.run([sys.executable, "test_unicorn_rep.py"], 
                       capture_output=True, text=True, timeout=10)
print(result.stdout)
if result.stderr:
    print("STDERR:", result.stderr)
print("Exit code:", result.returncode)
