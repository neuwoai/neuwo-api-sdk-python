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
        response_data: Raw response data (if available)
    """

    def __init__(
        self, message: str, status_code: int = None, response_data: dict = None
    ):
        """Initialize NeuwoAPIError.

        Args:
            message: Error message
            status_code: HTTP status code
            response_data: Raw response data from API
        """
        self.message = message
        self.status_code = status_code
        self.response_data = response_data or {}
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

    def __init__(
        self,
        message: str = "Unauthorized - Invalid or missing token",
        response_data: dict = None,
    ):
        """Initialize AuthenticationError."""
        super().__init__(message, status_code=401, response_data=response_data)


class ForbiddenError(NeuwoAPIError):
    """Raised when access is forbidden (403).

    This typically means the token lacks necessary permissions,
    or the requested resource is restricted.
    """

    def __init__(
        self,
        message: str = "Forbidden - Token lacks necessary permissions",
        response_data: dict = None,
    ):
        """Initialize ForbiddenError."""
        super().__init__(message, status_code=403, response_data=response_data)


class NotFoundError(NeuwoAPIError):
    """Raised when a resource is not found (404).

    For EDGE endpoints, this can mean the URL hasn't been processed yet
    and has been queued for crawling.
    """

    def __init__(self, message: str = "Resource not found", response_data: dict = None):
        """Initialize NotFoundError."""
        super().__init__(message, status_code=404, response_data=response_data)


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
        message: str = "Validation error",
        response_data: dict = None,
        validation_details: list = None,
    ):
        """Initialize ValidationError.

        Args:
            message: Error message
            response_data: Raw response data
            validation_details: List of validation error details
        """
        super().__init__(message, status_code=422, response_data=response_data)
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

    def __init__(self, message: str = "Bad request", response_data: dict = None):
        """Initialize BadRequestError."""
        super().__init__(message, status_code=400, response_data=response_data)


class RateLimitError(NeuwoAPIError):
    """Raised when API rate limits are exceeded (429).

    The client should wait before making additional requests.
    """

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        response_data: dict = None,
        retry_after: int = None,
    ):
        """Initialize RateLimitError.

        Args:
            message: Error message
            response_data: Raw response data
            retry_after: Seconds to wait before retrying (if provided by API)
        """
        super().__init__(message, status_code=429, response_data=response_data)
        self.retry_after = retry_after


class ServerError(NeuwoAPIError):
    """Raised when the server encounters an error (5xx).

    This indicates a problem on the API server side.
    """

    def __init__(
        self,
        message: str = "Server error",
        status_code: int = 500,
        response_data: dict = None,
    ):
        """Initialize ServerError."""
        super().__init__(message, status_code=status_code, response_data=response_data)


class NetworkError(NeuwoAPIError):
    """Raised when network communication fails.

    This can occur due to:
    - Connection timeouts
    - DNS resolution failures
    - Network unavailability
    """

    def __init__(
        self, message: str = "Network error occurred", original_error: Exception = None
    ):
        """Initialize NetworkError.

        Args:
            message: Error message
            original_error: The original exception that caused this error
        """
        super().__init__(message)
        self.original_error = original_error

    def __str__(self) -> str:
        """String representation with original error."""
        if self.original_error:
            return f"{self.message}: {str(self.original_error)}"
        return self.message


class ContentNotAvailableError(NeuwoAPIError):
    """Raised when content tagging could not be created.

    This specific error occurs when:
    - The page was unavailable
    - Edge processing couldn't find content to analyze
    """

    def __init__(self, url: str = None, message: str = None):
        """Initialize ContentNotAvailableError.

        Args:
            url: The URL that couldn't be processed
            message: Custom error message
        """
        self.url = url
        if message is None and url:
            message = f"Tagging not created for URL {url}. Page may be unavailable or content couldn't be analyzed."
        elif message is None:
            message = "Content could not be analyzed"
        super().__init__(message)


class NoDataAvailableError(NeuwoAPIError):
    """Raised when data is not yet available (URL not processed).

    For EDGE endpoints, this means the URL has been queued for processing
    and results will be available after crawling completes (typically 10-60 seconds).
    """

    def __init__(
        self, message: str = "No data yet available - URL queued for processing"
    ):
        """Initialize NoDataAvailableError."""
        super().__init__(message, status_code=404)
