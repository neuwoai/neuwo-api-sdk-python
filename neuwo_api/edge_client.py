"""
EDGE API client for Neuwo API.

This module provides a client for analysis where content is
identified by URL (websites).
"""

import time
from typing import Optional

import requests

from .exceptions import ContentNotAvailableError, NoDataAvailableError
from .logger import get_logger
from .models import GetAiTopicsResponse
from .utils import (
    RequestHandler,
    parse_json_response,
    validate_url,
)

logger = get_logger(__name__)


class NeuwoEdgeClient:
    """Client for Neuwo EDGE API endpoints.

    EDGE endpoints operate over standard HTTP methods and use an EDGE
    API token passed as a query parameter. EDGE endpoints are designed
    for client-side integration where content is identified by URL.
    The EDGE API serves publishers who want to enrich the data of
    published articles.

    Attributes:
        default_origin: Default origin header for requests
    """

    DEFAULT_TIMEOUT = 60

    def __init__(
        self,
        token: str,
        base_url: str,
        timeout: Optional[int] = None,
        default_origin: Optional[str] = None,
    ):
        """Initialize the EDGE API client.

        Args:
            token: EDGE API authentication token
            base_url: Base URL for the API server
            timeout: Request timeout in seconds (default: 60)
            default_origin: Default origin header for requests
                (e.g., "https://example.com")

        Raises:
            ValueError: If token is empty or invalid
        """
        if not token or not isinstance(token, str):
            raise ValueError("Token must be a non-empty string")
        token = token.strip()

        if not base_url or not isinstance(base_url, str):
            raise ValueError("Server base URL must be a non-empty string")
        base_url = base_url.rstrip("/")

        timeout = timeout or self.DEFAULT_TIMEOUT
        self.default_origin = default_origin

        # Initialize request handler
        self._request_handler = RequestHandler(
            token=token, base_url=base_url, timeout=timeout
        )

        logger.info(f"Initialized NeuwoEdgeClient with base_url: {base_url}")

    def get_ai_topics_raw(
        self, url: str, origin: Optional[str] = None
    ) -> requests.Response:
        """Retrieve AI-generated tags for a URL (raw response).

        Returns the raw HTTP response without parsing.

        Args:
            url: URL to identify and locate the article (required)
            origin: Origin header for the request (overrides default)

        Returns:
            Raw requests.Response object

        Raises:
            ValidationError: If URL is invalid
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NotFoundError: If URL not yet processed (queued for crawling)
            ContentNotAvailableError: If tagging could not be created
            NeuwoAPIError: For other API errors
        """
        # Validate URL
        validate_url(url)

        # Prepare query parameters
        params = {"url": url}

        # Prepare headers
        headers = {}
        if origin:
            headers["Origin"] = origin
        elif self.default_origin:
            headers["Origin"] = self.default_origin

        logger.info(f"Getting AI topics for URL: {url}")

        # Make request
        return self._request_handler.request(
            method="GET",
            endpoint="/edge/GetAiTopics",
            params=params,
            headers=headers if headers else None,
        )

    def get_ai_topics(
        self, url: str, origin: Optional[str] = None
    ) -> GetAiTopicsResponse:
        """Retrieve AI-generated tags and classifications for a URL.

                If the URL has been processed by the Neuwo crawler,
                returns tags,brand safety, marketing categories
                (IAB Content Taxonomy, IAB Audience Taxonomy, Google Topics),
                and smart tags for the article.

                When called for the first time with a specific URL or if the
                URL is still in the queue being processed, raises
                NoDataAvailableError (the URL is queued for processing, which
                typically takes 10-60 seconds).

                Args:
                    url: URL to identify and locate the article (required)
                    origin: Origin header for the request (overrides default)

                Returns:
                    GetAiTopicsResponse object containing tags, brand safety,
                    marketing categories, and smart tags

                Raises:
                    ValidationError: If URL is invalid
                    AuthenticationError: If token is invalid
                    ForbiddenError: If token lacks permissions
                    NoDataAvailableError: If URL not yet processed
        +                (queued for crawling)
                    ContentNotAvailableError: If tagging could not be created
                    NeuwoAPIError: For other API errors
        """
        response = self.get_ai_topics_raw(url=url, origin=origin)

        # Parse response (will raise ContentNotAvailableError if error
        # field present)
        response_data = parse_json_response(response)

        # Convert to model
        result = GetAiTopicsResponse.from_dict(response_data)

        logger.info(
            f"Retrieved {len(result.tags)} tags and "
            f"{len(result.smart_tags)} smart tags"
        )

        return result

    def get_ai_topics_wait(
        self,
        url: str,
        origin: Optional[str] = None,
        max_retries: int = 10,
        retry_interval: int = 6,
        initial_delay: int = 2,
    ) -> GetAiTopicsResponse:
        """Retrieve AI-generated tags for a URL with automatic retry on 404.

        This method automatically handles the case when a URL hasn't been
        processed yet. It will wait and retry multiple times until the
        data is available or max retries is reached. Typically processing
        takes 10-60 seconds for new URLs.

        Args:
            url: URL to identify and locate the article (required)
            origin: Origin header for the request (overrides default)
            max_retries: Maximum number of retry attempts (default: 10)
            retry_interval: Seconds to wait between retries (default: 6)
            initial_delay: Initial delay before first request in seconds
                (default: 2)

        Returns:
            GetAiTopicsResponse object containing tags, brand safety,
            marketing categories, and smart tags

        Raises:
            ValidationError: If URL is invalid
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NoDataAvailableError: If data not available after max retries
            ContentNotAvailableError: If tagging could not be created
            NeuwoAPIError: For other API errors
        """
        logger.info(
            f"Will retry up to {max_retries} times with "
            f"{retry_interval}s interval"
        )

        # Initial delay to give the system time to queue the request
        if initial_delay > 0:
            logger.info(
                f"Initial delay of {initial_delay}s before first request"
            )
            time.sleep(initial_delay)

        for attempt in range(max_retries + 1):
            try:
                logger.info(
                    f"Attempt {attempt + 1}/{max_retries + 1} to get AI topics"
                )
                return self.get_ai_topics(url=url, origin=origin)
            except NoDataAvailableError:
                # Handle 404 "No data yet available" error
                logger.debug(
                    f"Attempt {attempt + 1}/{max_retries + 1}: "
                    f"Data not yet available"
                )

                if attempt >= max_retries:
                    logger.error(
                        f"Max retries ({max_retries}) reached, giving up"
                    )
                    total_time = (max_retries * retry_interval) + initial_delay
                    raise NoDataAvailableError(
                        f"Data not available after {max_retries + 1} "
                        f"attempts ({total_time}s total). The URL may "
                        f"still be processing or unavailable."
                    )

                # Wait before retrying
                logger.info(
                    f"Waiting {retry_interval}s before retry "
                    f"{attempt + 2}/{max_retries + 1}..."
                )
                time.sleep(retry_interval)
            except ContentNotAvailableError as e:
                # Tagging could not be created - this is a permanent
                # error, don't retry
                logger.error(f"Content not available: {e}")
                raise

        # Should not reach here, but just in case
        raise NoDataAvailableError(f"Failed to get data for URL: {url}")
