"""
Utility functions for the Neuwo API SDK.

This module contains helper functions for URL validation,
response parsing, and other common operations.
"""

import json
from typing import Any, Dict, List, Optional
from urllib.parse import ParseResult, quote, urlencode, urlparse, urlunparse

import requests

from .exceptions import (
    AuthenticationError,
    BadRequestError,
    ContentNotAvailableError,
    ForbiddenError,
    NetworkError,
    NeuwoAPIError,
    NoDataAvailableError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)
from .logger import get_logger

logger = get_logger(__name__)


def validate_url(url: str) -> bool:
    """Validate that a string is a valid URL.

    Args:
        url: URL string to validate

    Returns:
        True if URL is valid

    Raises:
        ValidationError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL must be a non-empty string")

    url = url.strip()

    try:
        result = urlparse(url)
        # Check that scheme and netloc are present
        if not all([result.scheme, result.netloc]):
            raise ValidationError(f"Invalid URL format: {url}")

        # Check for valid scheme
        if result.scheme not in ["http", "https"]:
            raise ValidationError(f"URL must use http or https scheme: {url}")

        return True
    except Exception as e:
        if isinstance(e, ValidationError):
            raise
        raise ValidationError(f"Invalid URL: {url}") from e


def parse_json_response(response: requests.Response) -> Dict[str, Any]:
    """Parse JSON response into a dictionary.

    Args:
        response: HTTP response object from API

    Returns:
        Parsed dictionary

    Raises:
        ContentNotAvailableError: If response contains an error field
        NeuwoAPIError: If JSON parsing fails
    """
    response_text = response.text

    try:
        data = json.loads(response_text)

        # Check if response contains an error field (200 with error content)
        if isinstance(data, dict) and "error" in data:
            error_message = data["error"]
            url = data.get("url")

            logger.error(f"API returned error in response body: {error_message}")
            raise ContentNotAvailableError(message=error_message, url=url)

        return data
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON response: {e}")
        logger.debug(f"Response text: {response_text[:500]}")
        raise NeuwoAPIError(f"Invalid JSON response from API: {e}") from e


def prepare_url_list_file(urls: List[str]) -> bytes:
    """Prepare a comma-separated list of URLs for file upload.

    Args:
        urls: List of URL strings

    Returns:
        Bytes content for file upload

    Raises:
        ValidationError: If any URL is invalid
    """
    # Validate all URLs
    for url in urls:
        validate_url(url)

    # Create comma-separated list with no spaces
    content = ",".join(urls)
    return content.encode("utf-8")


def sanitize_content(content: str) -> str:
    """Sanitize content string and validate it's not empty.

    Args:
        content: Content string to sanitize

    Returns:
        Sanitized content string

    Raises:
        ValidationError: If content is empty or only whitespace
    """
    if not content or not isinstance(content, str):
        raise ValidationError("Content must be a non-empty string")

    content = content.strip()

    if not content:
        raise ValidationError("Cannot process only whitespace")

    return content


class RequestHandler:
    """Handles HTTP requests to the Neuwo API.

    This class encapsulates all HTTP request logic and can be reused
    by both REST and EDGE clients.

    Attributes:
        token: API authentication token
        base_url: Base URL for the API
        timeout: Request timeout in seconds
    """

    def __init__(self, token: str, base_url: str, timeout: int = 60):
        """Initialize the request handler.

        Args:
            token: API authentication token
            base_url: Base URL for the API
            timeout: Request timeout in seconds
        """

        self.token = token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._logger = get_logger(__name__)

    def _build_url(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> str:
        """Build full URL with query parameters including token.

        Args:
            endpoint: API endpoint path
            params: Optional query parameters to append

        Returns:
            Complete URL string with token and parameters
        """

        # Parse base URL
        parsed_base = urlparse(self.base_url)

        # Combine base URL with endpoint
        # Ensure endpoint starts with / for proper path joining
        if not endpoint.startswith("/"):
            endpoint = f"/{endpoint}"

        # Create full path
        full_path = f"{parsed_base.path}{endpoint}".rstrip("/")
        if not full_path:
            full_path = "/"

        # Build query parameters
        query_params = []

        # Always add token as query parameter
        query_params.append(f"token={quote(self.token)}")

        # Add additional parameters
        if params:
            for key, value in params.items():
                if value is not None:
                    if isinstance(value, list):
                        # For arrays, repeat the parameter name
                        for item in value:
                            query_params.append(f"{quote(str(key))}={quote(str(item))}")
                    else:
                        query_params.append(f"{quote(str(key))}={quote(str(value))}")

        query_string = "&".join(query_params)

        # Reconstruct URL
        url_parts = ParseResult(
            scheme=parsed_base.scheme,
            netloc=parsed_base.netloc,
            path=full_path,
            params="",
            query=query_string,
            fragment="",
        )

        return urlunparse(url_parts)

    @staticmethod
    def _encode_value(value: Any) -> str:
        """Encode a value for form data.

        Args:
            value: Value to encode (string, number, boolean, etc.)

        Returns:
            String representation of the value
        """
        if isinstance(value, bool):
            return str(value).lower()
        return str(value)

    def encode_form_data(self, data: Dict[str, Any]) -> str:
        """Encode data as application/x-www-form-urlencoded.

        Handles lists by repeating the parameter name for each value.
        For example: {'tags': ['a', 'b']} becomes 'tags=a&tags=b'

        Args:
            data: Dictionary of form fields

        Returns:
            URL-encoded form data string
        """
        pairs = []

        for key, value in data.items():
            if value is not None:
                if isinstance(value, list):
                    # Repeat parameter for each value in list
                    for item in value:
                        if item is not None:
                            pairs.append((key, self._encode_value(item)))
                else:
                    pairs.append((key, self._encode_value(value)))

        return urlencode(pairs, doseq=False)

    @staticmethod
    def handle_api_error(response: requests.Response) -> NeuwoAPIError:
        """Handle API error responses by parsing and creating appropriate exceptions.

        Parses the error response, extracts relevant error information, and maps
        HTTP status codes to specific exception types for better error handling.

        Args:
            response: HTTP response object with status code >= 400

        Returns:
            Appropriate exception instance based on the status code and error content
        """
        status_code = response.status_code
        response_text = response.text

        # Try to parse response as JSON
        try:
            error_data = response.json()
        except Exception:
            error_data = {}
            logger.debug("Could not parse error response as JSON")
            # Store raw response text as detail for non-JSON responses
            if response_text and len(response_text) < 500:
                detail = response_text

        logger.error(
            f"API error {status_code}: {error_data if error_data else response_text[:500]}"
        )

        # Extract message from response
        message = None
        detail = None

        if isinstance(error_data, dict):
            message = (
                error_data.get("message")
                or error_data.get("detail")
                or error_data.get("error")
            )

            # Store detail separately if it's not used as message
            if "detail" in error_data and message != error_data["detail"]:
                detail = error_data["detail"]

        # Fallback to response text if no message found
        if not message:
            if response_text and len(response_text) < 500:
                message = response_text
            else:
                message = f"API error with status {status_code}"

        # Merge detail into message if detail contains additional information
        if detail and not isinstance(detail, list):
            # Only merge if detail is a string and different from message
            if isinstance(detail, str) and detail != message:
                message = f"{message}: {detail}"
            elif isinstance(detail, dict):
                # For dict details, include them in the message
                message = f"{message}: {detail}"

        # Map status codes to exceptions
        if status_code == 400:
            return BadRequestError(message)
        elif status_code == 401:
            return AuthenticationError(message)
        elif status_code == 403:
            return ForbiddenError(message)
        elif status_code == 404:
            # Check if this is "No data yet available" error
            if "no data yet available" in message.lower():
                return NoDataAvailableError(message)
            return NotFoundError(message)
        elif status_code == 422:
            # Extract validation details if present
            validation_details = None
            if isinstance(detail, list):
                validation_details = detail
            elif isinstance(error_data.get("detail"), list):
                validation_details = error_data["detail"]

            if validation_details:
                return ValidationError(message, validation_details)
            return ValidationError(message)
        elif status_code == 429:
            # Extract retry_after from headers if present
            retry_after = None
            if hasattr(response, "headers") and "Retry-After" in response.headers:
                try:
                    retry_after = int(response.headers["Retry-After"])
                except (ValueError, TypeError):
                    logger.debug(
                        f"Could not parse Retry-After header: {response.headers['Retry-After']}"
                    )
            return RateLimitError(message, retry_after)
        elif status_code >= 500:
            return ServerError(message, status_code)
        else:
            return NeuwoAPIError(message, status_code)

    def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        """Make an HTTP request to the API.

        Args:
            method: HTTP method (GET, POST, PUT)
            endpoint: API endpoint path
            params: Query parameters
            data: Form data for POST/PUT requests
            headers: Additional HTTP headers
            files: Files to upload (for multipart/form-data)

        Returns:
            Response object

        Raises:
            NetworkError: On network failure or timeout
            NeuwoAPIError: On API error responses
        """
        # Build full URL with query parameters and token
        url = self._build_url(endpoint, params)

        # Prepare headers
        request_headers = headers or {}

        # Prepare request body
        encoded_data = None
        if data is not None and files is None:
            if "Content-Type" not in request_headers:
                request_headers["Content-Type"] = "application/x-www-form-urlencoded"
            encoded_data = self.encode_form_data(data)

        self._logger.debug(f"Making {method} request to {url}")

        try:
            response = requests.request(
                method=method,
                url=url,
                data=encoded_data if files is None else data,
                files=files,
                headers=request_headers,
                timeout=self.timeout,
            )

            self._logger.debug(f"Response status: {response.status_code}")

            # Handle error status codes
            if response.status_code >= 400:
                raise self.handle_api_error(response)

            return response

        except requests.exceptions.Timeout as e:
            self._logger.error(f"Request timeout after {self.timeout} seconds")
            raise NetworkError(f"Request timeout after {self.timeout} seconds", e)
        except requests.exceptions.ConnectionError as e:
            self._logger.error(f"Connection error: {e}")
            raise NetworkError("Failed to connect to API server", e)
        except requests.exceptions.RequestException as e:
            self._logger.error(f"Request failed: {e}")
            raise NetworkError(f"Request failed: {e}", e)
