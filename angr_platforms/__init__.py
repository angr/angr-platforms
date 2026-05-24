from __future__ import annotations

import sys


# Legacy tests and callers still import nested paths like
# ``angr_platforms.angr_platforms.X86_16...``. Keep that package alias alive
# while the real package root remains ``angr_platforms``.
sys.modules.setdefault("angr_platforms.angr_platforms", sys.modules[__name__])
