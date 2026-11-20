from .base import _FunctionalCPABE
from ..models import Scheme


class AC17CPABE(_FunctionalCPABE):
    """AC17 with the native hybrid payload encryption format."""
    _scheme = Scheme.AC17
