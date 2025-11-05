"""
Custom exceptions for the Neuwo API SDK.

This module defines all custom exceptions that can be raised
when interacting with the Neuwo API.
"""


class NeuwoAPIError(Exception):
    """Base exception for all Neuwo API errors.

    Attributes:
        message: Error message
        status_code: HTTP status code (if applicable)
    """

    def __init__(self, message: str, status_code: int = None):
        """Initialize NeuwoAPIError.

        Args:
            message: Error message
            status_code: HTTP status code
        """
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

    def __str__(self) -> str:
        """String representation of the error."""
        if self.status_code:
            return f"[{self.status_code}] {self.message}"
        return self.message


class AuthenticationError(NeuwoAPIError):
    """Raised when authentication fails (401).

    This typically means the API token is invalid or missing.
    """

    def __init__(self, message: str = "Unauthorised - Invalid or missing token"):
        """Initialize AuthenticationError."""
        super().__init__(message, status_code=401)


class ForbiddenError(NeuwoAPIError):
    """Raised when access is forbidden (403).

    This typically means the token lacks necessary permissions,
    or the requested resource is restricted.
    """

    def __init__(self, message: str = "Forbidden - Token lacks necessary permissions"):
        """Initialize ForbiddenError."""
        super().__init__(message, status_code=403)


class NotFoundError(NeuwoAPIError):
    """Raised when a resource is not found (404).

    For EDGE endpoints, this can mean the URL hasn't been processed yet
    and has been queued for crawling.
    """

    def __init__(self, message: str = "Not Found - Resource not found"):
        """Initialize NotFoundError."""
        super().__init__(message, status_code=404)


class ValidationError(NeuwoAPIError):
    """Raised when request validation fails (422).

    This can occur due to:
    - Missing required fields
    - Invalid field values
    - Content containing only whitespace
    - Other validation failures
    """

    def __init__(
        self,
        message: str = "Validation Error - Request validation failed",
        validation_details: list = None,
    ):
        """Initialize ValidationError.

        Args:
            message: Error message
            validation_details: List of validation error details
        """
        super().__init__(message, status_code=422)
        self.validation_details = validation_details or []

    def __str__(self) -> str:
        """String representation with validation details."""
        base_message = super().__str__()
        if self.validation_details:
            details = "\n".join(
                [
                    f"  - {detail.get('loc', [])}: {detail.get('msg', '')}"
                    for detail in self.validation_details
                ]
            )
            return f"{base_message}\nValidation errors:\n{details}"
        return base_message


class BadRequestError(NeuwoAPIError):
    """Raised when the request is malformed (400).

    This typically means required parameters are missing or invalid.
    """

    def __init__(self, message: str = "Bad Request - Malformed request"):
        """Initialize BadRequestError."""
        super().__init__(message, status_code=400)


class RateLimitError(NeuwoAPIError):
    """Raised when API rate limits are exceeded (429).

    The client should wait before making additional requests.
    """

    def __init__(
        self,
        message: str = "Rate Limit Exceeded - Too many requests",
        retry_after: int = None,
    ):
        """Initialize RateLimitError.

        Args:
            message: Error message
            retry_after: Seconds to wait before retrying (if provided by API)
        """
        super().__init__(message, status_code=429)
        self.retry_after = retry_after


class ServerError(NeuwoAPIError):
    """Raised when the server encounters an error (5xx).

    This indicates a problem on the API server side.
    """

    def __init__(
        self,
        message: str = "Server Error - Internal server error",
        status_code: int = 500,
    ):
        """Initialize ServerError."""
        super().__init__(message, status_code=status_code)


class NetworkError(NeuwoAPIError):
    """Raised when network communication fails.

    This exception uses Python's built-in exception chaining (__cause__)
    to preserve the original error context. Access the original exception
    via the __cause__ attribute.

    This can occur due to:
    - Connection timeouts
    - DNS resolution failures
    - Network unavailability
    """

    def __init__(
        self, message: str = "Network Error - Failed to communicate with server", original_error: Exception = None
    ):
        """Initialize NetworkError.

        Args:
            message: Error message
            original_error: The original exception that caused this error.
                          This will be set as __cause__ for proper exception chaining.
        """
        super().__init__(message)
        # Use Python's exception chaining mechanism
        if original_error is not None:
            self.__cause__ = original_error


class ContentNotAvailableError(NeuwoAPIError):
    """Raised when content tagging could not be created.

    This specific error occurs when:
    - The page was unavailable
    - Edge processing couldn't find content to analyze
    """

    def __init__(self, message: str = "Content Not Available - Tagging could not be created", 
                 url: str = None):
        """Initialize ContentNotAvailableError.

        Args:
            message: Custom error message
            url: The URL that couldn't be processed
        """
        super().__init__(message)
        self.url = url


class NoDataAvailableError(NotFoundError):
    """Raised when data is not yet available (URL not processed).

    This is a specialized NotFoundError (404) for EDGE endpoints, indicating
    the URL has been queued for processing and results will be available
    after crawling completes (typically 10-60 seconds).
    """

    def __init__(
        self, message: str = "No data yet available - URL queued for processing"
    ):
        """Initialize NoDataAvailableError."""
        super().__init__(message)
