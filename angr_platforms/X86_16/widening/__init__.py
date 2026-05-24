# Layer: Widening
# Responsibility: proven-safe joins and width propagation
# Forbidden: text-shape joins and CLI-driven recovery

from . import register_widening as _register_widening
from . import stack_widening as _stack_widening
from .store_width import *  # noqa: F401,F403
from .widening_rules import *  # noqa: F401,F403

globals().update(
    {
        name: getattr(_register_widening, name)
        for name in dir(_register_widening)
        if not name.startswith("__")
    }
)
globals().update(
    {
        name: getattr(_stack_widening, name)
        for name in dir(_stack_widening)
        if not name.startswith("__")
    }
)

__all__ = tuple(
    {
        *(
            name
            for name in dir(_register_widening)
            if not name.startswith("__")
        ),
        *(
            name
            for name in dir(_stack_widening)
            if not name.startswith("__")
        ),
    }
)
