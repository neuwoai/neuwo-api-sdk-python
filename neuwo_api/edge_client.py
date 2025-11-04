"""
EDGE API client for Neuwo API.

This module provides a client for analysis where content is identified by URL (websites).
"""

import time
from io import BytesIO
from typing import Any, Dict, List, Optional, Union

import requests

from .exceptions import ContentNotAvailableError, NoDataAvailableError
from .logger import get_logger
from .models import GetAiTopicsResponse, SimilarArticle
from .utils import (
    RequestHandler,
    parse_json_response,
    prepare_url_list_file,
    validate_url,
)

logger = get_logger(__name__)


class NeuwoEdgeClient:
    """Client for Neuwo EDGE API endpoints.

    EDGE endpoints operate over standard HTTP methods and use an EDGE API token passed as a query parameter. 
    EDGE endpoints are designed for client-side integration where content is identified by URL. 
    The EDGE API serves publishers who want to enrich the data of published articles.

    Attributes:
        token: EDGE API authentication token
        base_url: Base URL for the API
        timeout: Request timeout in seconds
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
            default_origin: Default origin header for requests (e.g., "https://example.com")

        Raises:
            ValueError: If token is empty or invalid
        """
        if not token or not isinstance(token, str):
            raise ValueError("Token must be a non-empty string")
        self.token = token.strip()

        if not base_url or not isinstance(base_url, str):
            raise ValueError("Server base URL must be a non-empty string")
        self.base_url = base_url.rstrip("/")

        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self.default_origin = default_origin

        # Initialize request handler
        self._request_handler = RequestHandler(
            token=self.token, base_url=self.base_url, timeout=self.timeout
        )

        logger.info(f"Initialized NeuwoEdgeClient with base_url: {self.base_url}")

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        """Make an HTTP request via the request handler.

        Args:
            method: HTTP method (GET, POST)
            endpoint: API endpoint path
            params: Query parameters
            data: Form data for POST requests
            headers: Additional HTTP headers
            files: Files to upload

        Returns:
            Response object
        """
        # Add origin header if configured
        if self.default_origin:
            if headers is None:
                headers = {}
            if "Origin" not in headers:
                headers["Origin"] = self.default_origin

        return self._request_handler.request(
            method=method,
            endpoint=endpoint,
            params=params,
            data=data,
            headers=headers,
            files=files,
        )

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
        return self._request(
            method="GET",
            endpoint="/edge/GetAiTopics",
            params=params,
            headers=headers if headers else None,
        )

    def get_ai_topics(
        self, url: str, origin: Optional[str] = None
    ) -> GetAiTopicsResponse:
        """Retrieve AI-generated tags and classifications for a URL.

        If the URL has been processed by the Neuwo crawler, returns tags, brand safety,
        marketing categories (IAB Content Taxonomy, IAB Audience Taxonomy, Google Topics),
        and smart tags for the article.

        When called for the first time with a specific URL or if the URL is still in the
        queue being processed, raises NoDataAvailableError (the URL is queued for
        processing, which typically takes 10-60 seconds).

        Args:
            url: URL to identify and locate the article (required)
            origin: Origin header for the request (overrides default)

        Returns:
            GetAiTopicsResponse object containing tags, brand safety, marketing categories, and smart tags

        Raises:
            ValidationError: If URL is invalid
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NoDataAvailableError: If URL not yet processed (queued for crawling)
            ContentNotAvailableError: If tagging could not be created
            NeuwoAPIError: For other API errors
        """
        response = self.get_ai_topics_raw(url=url, origin=origin)

        # Parse response (will raise ContentNotAvailableError if error field present)
        response_data = parse_json_response(response.text)

        # Convert to model
        result = GetAiTopicsResponse.from_dict(response_data)

        logger.info(
            f"Retrieved {len(result.tags)} tags and {len(result.smart_tags)} smart tags"
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

        This method automatically handles the case when a URL hasn't been processed yet.
        It will wait and retry multiple times until the data is available or max retries
        is reached. Typically processing takes 10-60 seconds for new URLs.

        Args:
            url: URL to identify and locate the article (required)
            origin: Origin header for the request (overrides default)
            max_retries: Maximum number of retry attempts (default: 10)
            retry_interval: Seconds to wait between retries (default: 6)
            initial_delay: Initial delay before first request in seconds (default: 2)

        Returns:
            GetAiTopicsResponse object containing tags, brand safety, marketing categories, and smart tags

        Raises:
            ValidationError: If URL is invalid
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NoDataAvailableError: If data not available after max retries
            ContentNotAvailableError: If tagging could not be created
            NeuwoAPIError: For other API errors
        """

        # Validate URL first
        validate_url(url)

        logger.info(f"Requesting AI topics for URL with wait: {url}")
        logger.info(
            f"Will retry up to {max_retries} times with {retry_interval}s interval"
        )

        # Initial delay to give the system time to queue the request
        if initial_delay > 0:
            logger.debug(f"Initial delay of {initial_delay}s before first request")
            time.sleep(initial_delay)

        for attempt in range(max_retries + 1):
            try:
                # Try to get the data
                result = self.get_ai_topics(url=url, origin=origin)

                # Success! Data is available
                logger.info(f"Successfully retrieved data on attempt {attempt + 1}")
                return result

            except NoDataAvailableError:
                # Handle 404 "No data yet available" error
                logger.debug(
                    f"Attempt {attempt + 1}/{max_retries + 1}: Data not yet available"
                )

                if attempt >= max_retries:
                    logger.error(f"Max retries ({max_retries}) reached, giving up")
                    raise NoDataAvailableError(
                        f"Data not available after {max_retries + 1} attempts ({(max_retries * retry_interval) + initial_delay}s total). "
                        f"The URL may still be processing or unavailable."
                    )

                # Wait before retrying
                logger.info(
                    f"Waiting {retry_interval}s before retry {attempt + 2}/{max_retries + 1}..."
                )
                time.sleep(retry_interval)

            except ContentNotAvailableError as e:
                # Tagging could not be created - this is a permanent error, don't retry
                logger.error(f"Content not available: {e}")
                raise

        # Should not reach here, but just in case
        raise NoDataAvailableError(f"Failed to get data for URL: {url}")

    def get_ai_topics_list_raw(
        self, urls: Union[List[str], bytes], origin: Optional[str] = None
    ) -> requests.Response:
        """Retrieve AI-generated tags for multiple URLs (raw response).

        Returns the raw HTTP response without parsing.

        Args:
            urls: List of URL strings or bytes content of comma-separated URLs
            origin: Origin header for the request (overrides default)

        Returns:
            Raw requests.Response object

        Raises:
            ValidationError: If any URL is invalid
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NotFoundError: If no URLs have been processed yet
            NeuwoAPIError: For other API errors
        """
        # Prepare file content
        if isinstance(urls, list):
            file_content = prepare_url_list_file(urls)
            logger.info(f"Getting AI topics for {len(urls)} URLs")
        else:
            file_content = urls
            logger.info("Getting AI topics for URL list")

        # Prepare file for upload
        files = {"urllist": ("urllist.txt", BytesIO(file_content), "text/plain")}

        # Prepare headers
        headers = {}
        if origin:
            headers["Origin"] = origin
        elif self.default_origin:
            headers["Origin"] = self.default_origin

        # Make request
        return self._request(
            method="POST",
            endpoint="/edge/GetAiTopicsList",
            files=files,
            headers=headers if headers else None,
        )

    def get_ai_topics_list(
        self, urls: Union[List[str], bytes], origin: Optional[str] = None
    ) -> List[GetAiTopicsResponse]:
        """Retrieve AI-generated tags and classifications for multiple URLs.

        Accepts a list of URLs and returns AI-generated tag classifications for each URL
        that has been processed by the Neuwo crawler. If one or more URLs have not been
        processed, the response will include results only for previously analyzed URLs.
        Unprocessed URLs are queued for crawling and will be available in subsequent
        requests after processing completes (typically 5-10 seconds per URL).

        Note: Individual URLs that have errors (e.g., tagging not created) will raise
        ContentNotAvailableError during parsing. This method only returns successfully
        analyzed URLs.

        Args:
            urls: List of URL strings or bytes content of comma-separated URLs
            origin: Origin header for the request (overrides default)

        Returns:
            List of GetAiTopicsResponse objects, one for each successfully analyzed URL

        Raises:
            ValidationError: If any URL is invalid
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NotFoundError: If no URLs have been processed yet
            ContentNotAvailableError: If tagging could not be created for a URL
            NeuwoAPIError: For other API errors
        """
        response = self.get_ai_topics_list_raw(urls=urls, origin=origin)

        # Parse response
        response_data = parse_json_response(response.text)

        # Convert to models
        if not isinstance(response_data, list):
            logger.warning(f"Expected list response, got: {type(response_data)}")
            return []

        results = []
        for item in response_data:
            # Check if this item has an error field
            if isinstance(item, dict) and "error" in item:
                error_message = item["error"]
                url = item.get("url")
                logger.warning(f"Error for URL {url}: {error_message}")
                # Raise exception for the first error encountered
                raise ContentNotAvailableError(url=url, message=error_message)

            results.append(GetAiTopicsResponse.from_dict(item))

        logger.info(f"Retrieved results for {len(results)} URLs")

        return results

    def get_similar_raw(
        self,
        document_url: str,
        max_rows: Optional[int] = None,
        past_days: Optional[int] = None,
        publication_ids: Optional[List[str]] = None,
        origin: Optional[str] = None,
    ) -> requests.Response:
        """Find similar articles by URL (raw response).

        Returns the raw HTTP response without parsing.

        Args:
            document_url: Article URL to find similar articles for (required)
            max_rows: Limit how many similar articles are returned
            past_days: Limit search by ignoring articles older than specified days
            publication_ids: List of publication IDs to filter results
            origin: Origin header for the request (overrides default)

        Returns:
            Raw requests.Response object

        Raises:
            ValidationError: If URL is invalid
            BadRequestError: If document_url parameter is missing
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NotFoundError: If no similar articles found
            NeuwoAPIError: For other API errors
        """
        # Validate URL
        validate_url(document_url)

        # Prepare query parameters
        params = {"document_url": document_url}

        if max_rows is not None:
            params["max_rows"] = max_rows
        if past_days is not None:
            params["past_days"] = past_days
        if publication_ids is not None:
            params["publicationid"] = publication_ids

        # Prepare headers
        headers = {}
        if origin:
            headers["Origin"] = origin
        elif self.default_origin:
            headers["Origin"] = self.default_origin

        logger.info(f"Getting similar articles for URL: {document_url}")

        # Make request
        return self._request(
            method="GET",
            endpoint="/edge/GetSimilar",
            params=params,
            headers=headers if headers else None,
        )

    def get_similar(
        self,
        document_url: str,
        max_rows: Optional[int] = None,
        past_days: Optional[int] = None,
        publication_ids: Optional[List[str]] = None,
        origin: Optional[str] = None,
    ) -> List[SimilarArticle]:
        """Find articles similar to the specified document URL.

        Returns a list of similar articles with metadata including articleID, headline,
        articleURL, imageURL, similarity score, publication date, and publication ID.

        Args:
            document_url: Article URL to find similar articles for (required)
            max_rows: Limit how many similar articles are returned
            past_days: Limit search by ignoring articles older than specified days
            publication_ids: List of publication IDs to filter results
            origin: Origin header for the request (overrides default)

        Returns:
            List of SimilarArticle objects

        Raises:
            ValidationError: If URL is invalid
            BadRequestError: If document_url parameter is missing
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NotFoundError: If no similar articles found
            NeuwoAPIError: For other API errors
        """
        response = self.get_similar_raw(
            document_url=document_url,
            max_rows=max_rows,
            past_days=past_days,
            publication_ids=publication_ids,
            origin=origin,
        )

        # Parse response
        response_data = parse_json_response(response.text)

        # Convert to models
        if not isinstance(response_data, list):
            logger.warning(f"Expected list response, got: {type(response_data)}")
            return []

        similar_articles = [SimilarArticle.from_dict(item) for item in response_data]

        logger.info(f"Found {len(similar_articles)} similar articles")

        return similar_articles
