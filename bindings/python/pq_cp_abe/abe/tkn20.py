from .base import _FunctionalCPABE
from ..models import Scheme


class TKN20CPABE(_FunctionalCPABE):
    """TKN20 with the native hybrid payload encryption format."""
    _scheme = Scheme.TKN20
