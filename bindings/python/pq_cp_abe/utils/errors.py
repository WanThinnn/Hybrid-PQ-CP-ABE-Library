"""Native error translation shared by modern APIs."""
from .._native import abe_lib

class AbeError(RuntimeError):
    """Native operation failure; code preserves the C ABI error number."""

    def __init__(self, code: int, operation: str):
        self.code = code
        self.operation = operation
        message = abe_lib.getErrorMessage(code)
        detail = message.decode("utf-8", errors="replace") if message else "Native operation failed"
        super().__init__(f"{operation}: {detail} (code: {code})")


class PolicyMismatchError(AbeError):
    """The user's attributes do not satisfy the ciphertext policy."""


class SignatureInvalidError(AbeError):
    """Signature verification failed."""


def check_status(code: int, operation: str) -> None:
    if code:
        error = {-3: PolicyMismatchError, -9: SignatureInvalidError}.get(code, AbeError)
        raise error(code, operation)

