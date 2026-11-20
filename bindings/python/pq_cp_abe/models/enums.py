"""Algorithm identifiers shared by functional and object APIs."""
from enum import IntEnum

class Scheme(IntEnum):
    AC17 = 0
    TKN20 = 1
    COVERCRYPT = 2


class KemMode(IntEnum):
    CLASSIC = 0
    POST_QUANTUM = 1
    HYBRIDIZED = 2


class MlDsaParameterSet(IntEnum):
    ML_DSA_44 = 44
    ML_DSA_65 = 65
    ML_DSA_87 = 87


class MlKemParameterSet(IntEnum):
    ML_KEM_512 = 512
    ML_KEM_768 = 768
    ML_KEM_1024 = 1024

