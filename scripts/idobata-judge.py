#!/usr/bin/python3 -I
"""DSH環境の既存Qwenによる、明示したprivate対象だけの判断runner。"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from idobata_judge import main

if __name__ == '__main__':
    raise SystemExit(main())
