import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ANGR_PLATFORMS_ROOT = Path(__file__).resolve().parents[1]

for path in (REPO_ROOT, ANGR_PLATFORMS_ROOT):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
