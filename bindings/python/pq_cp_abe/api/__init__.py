"""Modern functions plus compatible historical imports.

Canonical implementations live in functional and legacy respectively.
"""
from . import legacy, functional
from .legacy import *
from .functional import *
__all__ = list(dict.fromkeys(legacy.__all__ + functional.__all__))
