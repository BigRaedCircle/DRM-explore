#!/bin/bash
# Run Python tests with proper UTF-8 encoding

export PYTHONIOENCODING=utf-8
python demos/test_cpuz_detailed.py 2>&1 | tail -60
