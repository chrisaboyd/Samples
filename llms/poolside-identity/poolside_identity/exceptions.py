"""Custom exceptions for Poolside Identity API."""


class PoolsideIdentityError(Exception):
    """Base exception for Poolside Identity API errors."""

    pass


class APIKeyError(PoolsideIdentityError):
    """Raised when API key is missing or invalid."""

    pass


class NotFoundError(PoolsideIdentityError):
    """Raised when a resource is not found."""

    pass


class ValidationError(PoolsideIdentityError):
    """Raised when request validation fails."""

    pass


class APIError(PoolsideIdentityError):
    """Raised when the API returns an error response."""

    def __init__(self, message: str, status_code: int = 0, detail: str | None = None):
        self.status_code = status_code
        self.detail = detail
        super().__init__(message)