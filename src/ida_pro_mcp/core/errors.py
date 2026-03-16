"""Shared error types for idap."""


class IDAPError(RuntimeError):
    """Structured idap error with a stable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self) -> dict[str, str]:
        return {"error": self.message, "code": self.code}
