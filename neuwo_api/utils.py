"""
Utility functions for the Neuwo API SDK.

This module contains helper functions for URL validation,
response parsing, and other common operations.
"""

import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse

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


def parse_json_response(response_text: str) -> Dict[str, Any]:
    """Parse JSON response text into a dictionary.

    Args:
        response_text: JSON string from API response

    Returns:
        Parsed dictionary

    Raises:
        ContentNotAvailableError: If response contains an error field
        NeuwoAPIError: If JSON parsing fails
    """
    try:
        data = json.loads(response_text)

        # Check if response contains an error field (200 with error content)
        if isinstance(data, dict) and "error" in data:
            error_message = data["error"]
            url = data.get("url")

            logger.error(f"API returned error in response body: {error_message}")
            raise ContentNotAvailableError(url=url, message=error_message)

        return data
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON response: {e}")
        logger.debug(f"Response text: {response_text[:500]}")
        raise NeuwoAPIError(f"Invalid JSON response from API: {e}") from e


def parse_xml_response(response_text: str) -> Dict[str, Any]:
    """Parse XML response text into a dictionary.

    This function converts XML responses from the Neuwo API into
    a dictionary structure that matches the JSON format.

    Args:
        response_text: XML string from API response

    Returns:
        Parsed dictionary

    Raises:
        NeuwoAPIError: If XML parsing fails
    """
    try:
        root = ET.fromstring(response_text)
        return _xml_element_to_dict(root)
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML response: {e}")
        logger.debug(f"Response text: {response_text[:500]}")
        raise NeuwoAPIError(f"Invalid XML response from API: {e}") from e


def _xml_element_to_dict(element: ET.Element) -> Dict[str, Any]:
    """Convert an XML element to a dictionary.

    Handles the specific XML structure used by Neuwo API responses.

    Args:
        element: XML element to convert

    Returns:
        Dictionary representation of the XML element
    """
    result: Dict[str, Any] = {}

    # Handle attributes
    if element.attrib:
        result.update(element.attrib)

    # Handle text content
    if element.text and element.text.strip():
        # If element has no children, return text directly
        if len(element) == 0:
            return element.text.strip()

    # Handle child elements
    for child in element:
        child_data = _xml_element_to_dict(child)

        # Handle multiple elements with same tag (arrays)
        if child.tag in result:
            # Convert to list if not already
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(child_data)
        else:
            result[child.tag] = child_data

    return result


def build_query_string(params: Dict[str, Any]) -> str:
    """Build a URL query string from parameters.

    Handles multiple values for the same parameter name.

    Args:
        params: Dictionary of query parameters

    Returns:
        URL-encoded query string
    """

    # Filter out None values
    filtered_params = {}
    for key, value in params.items():
        if value is not None:
            # Handle lists (for parameters that can be repeated)
            if isinstance(value, list):
                filtered_params[key] = value
            else:
                filtered_params[key] = value

    # Build query string
    parts = []
    for key, value in filtered_params.items():
        if isinstance(value, list):
            # Repeat parameter for each value
            for item in value:
                parts.append(f"{quote(str(key))}={quote(str(item))}")
        else:
            parts.append(f"{quote(str(key))}={quote(str(value))}")

    return "&".join(parts)


def build_form_data(data: Dict[str, Any]) -> str:
    """Build URL-encoded form data from dictionary.

    Handles lists by repeating the parameter name for each value.
    For example: {'tags': ['a', 'b']} becomes 'tags=a&tags=b'

    Args:
        data: Dictionary of form fields

    Returns:
        URL-encoded form data string
    """

    # Filter out None values
    filtered_data = {k: v for k, v in data.items() if v is not None}

    # Build form data parts
    parts = []
    for key, value in filtered_data.items():
        if isinstance(value, list):
            # Repeat parameter for each value in list
            for item in value:
                parts.append(f"{quote(str(key))}={quote(str(item))}")
        elif isinstance(value, bool):
            # Convert boolean to lowercase string
            parts.append(f"{quote(str(key))}={quote(str(value).lower())}")
        else:
            parts.append(f"{quote(str(key))}={quote(str(value))}")

    return "&".join(parts)


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
            NetworkError: If network request fails
            NeuwoAPIError: If API returns an error
        """

        url = f"{self.base_url}{endpoint}"

        # Add token to params
        if params is None:
            params = {}
        params["token"] = self.token

        # Prepare headers
        request_headers = headers or {}

        # Prepare form data
        encoded_data = None
        if data is not None and files is None:
            if "Content-Type" not in request_headers:
                request_headers["Content-Type"] = "application/x-www-form-urlencoded"
            encoded_data = build_form_data(data)

        self._logger.debug(f"Making {method} request to {url}")
        self._logger.debug(f"Query params: {params}")
        if data:
            self._logger.debug(f"Form data keys: {list(data.keys())}")

        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                data=encoded_data if files is None else data,
                files=files,
                headers=request_headers,
                timeout=self.timeout,
            )

            self._logger.debug(f"Response status: {response.status_code}")

            # Handle error status codes
            if response.status_code >= 400:
                try:
                    error_data = response.json()
                except Exception:
                    error_data = {"detail": response.text}

                self._logger.error(f"API error {response.status_code}: {error_data}")

                error = self.handle_api_error(response.status_code, error_data)
                raise error

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

    @staticmethod
    def handle_api_error(
        status_code: int, response_data: Dict[str, Any]
    ) -> NeuwoAPIError:
        """Create appropriate exception based on status code and response.

        Args:
            status_code: HTTP status code
            response_data: Parsed response data

        Returns:
            Appropriate exception instance
        """

        # Extract message from response
        message = (
            response_data.get("message")
            or response_data.get("detail")
            or response_data.get("error")
            or f"API error with status {status_code}"
        )

        # Map status codes to exceptions
        if status_code == 400:
            return BadRequestError(message, response_data)
        elif status_code == 401:
            return AuthenticationError(message, response_data)
        elif status_code == 403:
            return ForbiddenError(message, response_data)
        elif status_code == 404:
            # Check if this is "No data yet available" error
            if "no data yet available" in message.lower():
                return NoDataAvailableError(message)
            return NotFoundError(message, response_data)
        elif status_code == 422:
            # Extract validation details if present
            validation_details = response_data.get("detail")
            if isinstance(validation_details, list):
                return ValidationError(message, response_data, validation_details)
            return ValidationError(message, response_data)
        elif status_code >= 500:
            return ServerError(message, status_code, response_data)
        else:
            return NeuwoAPIError(message, status_code, response_data)
