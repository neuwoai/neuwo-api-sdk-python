"""
REST API client for Neuwo API.

This module provides a client for analysis where content is provided directly as text.
"""

from datetime import date
from typing import List, Optional

import requests

from .exceptions import ValidationError
from .logger import get_logger
from .models import (
    Article,
    GetAiTopicsResponse,
    SimilarArticle,
    TrainingTag,
)
from .utils import (
    RequestHandler,
    parse_json_response,
    sanitize_content,
)

logger = get_logger(__name__)


class NeuwoRestClient:
    """Client for Neuwo REST API endpoints.

    REST endpoints operate over standard HTTP methods and use a REST API token passed as a query parameter.
    REST endpoints are designed for server-side integration where content is provided directly as text.
    The REST API serves publishers who want to enrich the data before publishing by analysing content.
    """

    DEFAULT_TIMEOUT = 60

    def __init__(self, token: str, base_url: str, timeout: Optional[int] = None):
        """Initialize the REST API client.

        Args:
            token: REST API authentication token
            base_url: Base URL for the API server
            timeout: Request timeout in seconds (default: 60)

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

        # Initialize request handler
        self._request_handler = RequestHandler(
            token=token, base_url=base_url, timeout=timeout
        )

        logger.info(f"Initialized NeuwoRestClient with base_url: {base_url}")

    def get_ai_topics_raw(
        self,
        content: str,
        document_id: Optional[str] = None,
        format: str = "json",
        lang: Optional[str] = None,
        publication_id: Optional[str] = None,
        headline: Optional[str] = None,
        tag_limit: int = 15,
        tag_min_score: float = 0.1,
        marketing_limit: Optional[int] = None,
        marketing_min_score: float = 0.3,
        include_in_sim: bool = True,
        article_url: Optional[str] = None,
    ) -> requests.Response:
        """Retrieve AI-generated tags (raw response).

        Returns the raw HTTP response without parsing. Useful for custom processing
        or debugging.

        Args:
            content: Text content to analyze (required)
            document_id: Unique identifier for the document/article
            format: Response format ("json" or "xml", default: "json")
            lang: ISO 639-1 language code (auto-detected if not provided)
            publication_id: Name of the publication
            headline: Headline associated with the content
            tag_limit: Maximum number of tags (max 25, default: 15)
            tag_min_score: Minimum score threshold for tags (default: 0.1)
            marketing_limit: Maximum number of marketing categories
            marketing_min_score: Minimum score threshold for marketing categories (default: 0.3)
            include_in_sim: Whether to include in similarity model (default: True)
            article_url: URL of the article

        Returns:
            Raw requests.Response object

        Raises:
            ValidationError: If content is empty or invalid
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            ValidationError: If request validation fails
            NeuwoAPIError: For other API errors
        """
        # Validate and sanitize content
        content = sanitize_content(content)

        # Prepare form data with required parameters
        data = {
            "content": content,
            "format": format,
            "tag_limit": tag_limit,
            "tag_min_score": tag_min_score,
            "marketing_min_score": marketing_min_score,
            "include_in_sim": include_in_sim,
        }

        # Add optional parameters
        if document_id is not None:
            data["documentid"] = document_id
        if lang is not None:
            data["lang"] = lang
        if publication_id is not None:
            data["publicationid"] = publication_id
        if headline is not None:
            data["headline"] = headline
        if marketing_limit is not None:
            data["marketing_limit"] = marketing_limit
        if article_url is not None:
            data["articleURL"] = article_url

        logger.info(f"Getting AI topics for content (length: {len(content)})")

        # Make request
        return self._request_handler.request(method="POST", endpoint="/GetAiTopics", data=data)

    def get_ai_topics(
        self,
        content: str,
        document_id: Optional[str] = None,
        lang: Optional[str] = None,
        publication_id: Optional[str] = None,
        headline: Optional[str] = None,
        tag_limit: int = 15,
        tag_min_score: float = 0.1,
        marketing_limit: Optional[int] = None,
        marketing_min_score: float = 0.3,
        include_in_sim: bool = True,
        article_url: Optional[str] = None,
    ) -> GetAiTopicsResponse:
        """Retrieve AI-generated tags and classifications for text content.

        Sends text content to Neuwo's REST API to obtain AI-generated tag classifications
        including subject tags, brand safety, marketing categories (IAB taxonomies), and
        smart tags. Optionally saves the article in the database if document_id is provided.

        Args:
            content: Text content to analyze (required)
            document_id: Unique identifier for the document/article
            lang: ISO 639-1 language code (auto-detected if not provided)
            publication_id: Name of the publication
            headline: Headline associated with the content
            tag_limit: Maximum number of tags (max 25, default: 15)
            tag_min_score: Minimum score threshold for tags (default: 0.1)
            marketing_limit: Maximum number of marketing categories
            marketing_min_score: Minimum score threshold for marketing categories (default: 0.3)
            include_in_sim: Whether to include in similarity model (default: True)
            article_url: URL of the article

        Returns:
            GetAiTopicsResponse object containing tags, brand safety, marketing categories, and smart tags

        Raises:
            ValidationError: If content is empty or invalid
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            ValidationError: If request validation fails
            NeuwoAPIError: For other API errors
        """
        response = self.get_ai_topics_raw(
            content=content,
            document_id=document_id,
            format="json",
            lang=lang,
            publication_id=publication_id,
            headline=headline,
            tag_limit=tag_limit,
            tag_min_score=tag_min_score,
            marketing_limit=marketing_limit,
            marketing_min_score=marketing_min_score,
            include_in_sim=include_in_sim,
            article_url=article_url,
        )

        # Parse response
        response_data = parse_json_response(response)

        # Convert to model
        result = GetAiTopicsResponse.from_dict(response_data)

        logger.info(
            f"Retrieved {len(result.tags)} tags and {len(result.smart_tags)} smart tags"
        )

        return result

    def get_similar_raw(
        self,
        document_id: str,
        format: str = "json",
        max_rows: Optional[int] = None,
        past_days: Optional[int] = None,
        publication_ids: Optional[List[str]] = None,
    ) -> requests.Response:
        """Find similar articles (raw response).

        Returns the raw HTTP response without parsing.

        Args:
            document_id: Unique identifier of the document/article (required)
            format: Response format ("json" or "xml", default: "json")
            max_rows: Limit how many similar articles are returned
            past_days: Limit search by ignoring articles older than specified days
            publication_ids: List of publication IDs to filter results

        Returns:
            Raw requests.Response object

        Raises:
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NotFoundError: If no similar articles found
            NeuwoAPIError: For other API errors
        """
        # Prepare query parameters
        params = {"documentid": document_id, "format": format}

        if max_rows is not None:
            params["max_rows"] = max_rows
        if past_days is not None:
            params["past_days"] = past_days
        if publication_ids is not None:
            params["publicationid"] = publication_ids

        logger.info(f"Getting similar articles for document: {document_id}")

        # Make request
        return self._request_handler.request(method="GET", endpoint="/GetSimilar", params=params)

    def get_similar(
        self,
        document_id: str,
        max_rows: Optional[int] = None,
        past_days: Optional[int] = None,
        publication_ids: Optional[List[str]] = None,
    ) -> List[SimilarArticle]:
        """Find articles similar to the specified document.

        Returns a list of similar articles with metadata including articleID, headline,
        articleURL, imageURL, similarity score, publication date, and publication ID.
        The score is a distance-type metric where lower values indicate better similarity.

        The similarity model is created with the customer's own history data and is
        customer-specific. Customer's own history is used to return the similar article predictions.

        Args:
            document_id: Unique identifier of the document/article (required)
            max_rows: Limit how many similar articles are returned
            past_days: Limit search by ignoring articles older than specified days
            publication_ids: List of publication IDs to filter results

        Returns:
            List of SimilarArticle objects

        Raises:
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NotFoundError: If no similar articles found
            NeuwoAPIError: For other API errors
        """
        response = self.get_similar_raw(
            document_id=document_id,
            format="json",
            max_rows=max_rows,
            past_days=past_days,
            publication_ids=publication_ids,
        )

        # Parse response
        response_data = parse_json_response(response)

        # Convert to models
        if not isinstance(response_data, list):
            logger.warning(f"Expected list response, got: {type(response_data)}")
            return []

        similar_articles = [SimilarArticle.from_dict(item) for item in response_data]

        logger.info(f"Found {len(similar_articles)} similar articles")

        return similar_articles

    def update_article_raw(
        self,
        document_id: str,
        published: Optional[date] = None,
        headline: Optional[str] = None,
        writer: Optional[str] = None,
        category: Optional[str] = None,
        content: Optional[str] = None,
        summary: Optional[str] = None,
        publication_id: Optional[str] = None,
        article_url: Optional[str] = None,
        image_url: Optional[str] = None,
        format: str = "json",
        include_in_sim: Optional[bool] = None,
    ) -> requests.Response:
        """Update article fields (raw response).

        Returns the raw HTTP response without parsing.

        Args:
            document_id: Unique identifier of the document/article (required)
            published: Date when the article was published (YYYY-MM-DD)
            headline: Headline of the article
            writer: Writer of the article
            category: Category of the article
            content: Article content
            summary: Summary of the article
            publication_id: Name of the publication
            article_url: URL of the article
            image_url: URL of the main image (deprecated)
            format: Response format ("json" or "xml", default: "json")
            include_in_sim: Whether article is included in similarity model

        Returns:
            Raw requests.Response object

        Raises:
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NotFoundError: If article not found
            ValidationError: If validation fails or content is only whitespace
            NeuwoAPIError: For other API errors
        """
        # Prepare form data
        data = {"format": format}

        # Add optional parameters
        if published is not None:
            data["published"] = published.strftime("%Y-%m-%d")
        if headline is not None:
            data["headline"] = headline
        if writer is not None:
            data["writer"] = writer
        if category is not None:
            data["category"] = category
        if content is not None:
            data["content"] = content
        if summary is not None:
            data["summary"] = summary
        if publication_id is not None:
            data["publicationid"] = publication_id
        if article_url is not None:
            data["articleURL"] = article_url
        if image_url is not None:
            data["imageURL"] = image_url
        if include_in_sim is not None:
            data["include_in_sim"] = include_in_sim

        logger.info(f"Updating article: {document_id}")

        # Make request
        return self._request_handler.request(
            method="PUT", endpoint=f"/UpdateArticle/{document_id}", data=data
        )

    def update_article(
        self,
        document_id: str,
        published: Optional[date] = None,
        headline: Optional[str] = None,
        writer: Optional[str] = None,
        category: Optional[str] = None,
        content: Optional[str] = None,
        summary: Optional[str] = None,
        publication_id: Optional[str] = None,
        article_url: Optional[str] = None,
        image_url: Optional[str] = None,
        include_in_sim: Optional[bool] = None,
    ) -> Article:
        """Update article fields in the database.

        This endpoint can only be used with articles that were assigned a document_id
        when analyzing with get_ai_topics(). Only fields provided in the request
        will be updated. Returns the updated article with all fields.

        Args:
            document_id: Unique identifier of the document/article (required)
            published: Date when the article was published (YYYY-MM-DD)
            headline: Headline of the article
            writer: Writer of the article
            category: Category of the article
            content: Article content
            summary: Summary of the article
            publication_id: Name of the publication
            article_url: URL of the article
            image_url: URL of the main image (deprecated)
            include_in_sim: Whether article is included in similarity model

        Returns:
            Article object with all fields (updated and unchanged)

        Raises:
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NotFoundError: If article not found
            ValidationError: If validation fails or content is only whitespace
            NeuwoAPIError: For other API errors
        """
        response = self.update_article_raw(
            document_id=document_id,
            published=published,
            headline=headline,
            writer=writer,
            category=category,
            content=content,
            summary=summary,
            publication_id=publication_id,
            article_url=article_url,
            image_url=image_url,
            format="json",
            include_in_sim=include_in_sim,
        )

        # Parse response
        response_data = parse_json_response(response)

        # Convert to model
        article = Article.from_dict(response_data)

        logger.info(f"Successfully updated article: {document_id}")

        return article

    def train_ai_topics_raw(
        self, document_id: str, tags: List[str], format: str = "json"
    ) -> requests.Response:
        """Save training tags for an article (raw response).

        Returns the raw HTTP response without parsing.

        Args:
            document_id: Unique identifier of the document/article (required)
            tags: List of training tag values to add to the article (required)
            format: Response format ("json" or "xml", default: "json")

        Returns:
            Raw requests.Response object

        Raises:
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NotFoundError: If article not found
            ValidationError: If no training tag values provided
            NeuwoAPIError: For other API errors
        """
        if not tags or not isinstance(tags, list) or len(tags) == 0:
            raise ValidationError("You must provide some TrainingTag values")

        # Prepare form data
        data = {"documentid": document_id, "tags": tags, "format": format}

        logger.info(f"Adding {len(tags)} training tags to article: {document_id}")

        # Make request
        return self._request_handler.request(method="POST", endpoint="/TrainAiTopics", data=data)

    def train_ai_topics(
        self,
        document_id: str,
        tags: List[str],
    ) -> List[TrainingTag]:
        """Save training tags for an article.

        Saves a list of training tags for an article in the database.
        Returns all newly added TrainingTags (tags that weren't already in the database).
        If all tags already exist, returns an empty list.

        Args:
            document_id: Unique identifier of the document/article (required)
            tags: List of training tag values to add to the article (required)

        Returns:
            List of newly added TrainingTag objects

        Raises:
            AuthenticationError: If token is invalid
            ForbiddenError: If token lacks permissions
            NotFoundError: If article not found
            ValidationError: If no training tag values provided
            NeuwoAPIError: For other API errors
        """
        response = self.train_ai_topics_raw(
            document_id=document_id, tags=tags, format="json"
        )

        # Parse response
        response_data = parse_json_response(response)

        # Convert to models
        if not isinstance(response_data, list):
            logger.warning(f"Expected list response, got: {type(response_data)}")
            return []

        training_tags = [TrainingTag.from_dict(item) for item in response_data]

        logger.info(f"Added {len(training_tags)} new training tags")

        return training_tags
