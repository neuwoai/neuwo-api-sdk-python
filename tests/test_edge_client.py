"""
Unit tests for Neuwo EDGE API client.
"""

from unittest.mock import Mock, patch

import pytest

from neuwo_api.edge_client import NeuwoEdgeClient
from neuwo_api.exceptions import (
    ContentNotAvailableError,
    NoDataAvailableError,
    ValidationError,
)


class TestNeuwoEdgeClientInit:
    """Tests for NeuwoEdgeClient initialization."""

    def test_init_with_token(self):
        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")
        assert client.token == "test-token"
        assert client.base_url == "https://custom.api.com"
        assert client.timeout == 60
        assert client.default_origin is None

    def test_init_with_origin(self):
        client = NeuwoEdgeClient(
            token="test-token",
            base_url="https://custom.api.com",
            default_origin="https://example.com",
        )
        assert client.default_origin == "https://example.com"

    def test_init_with_custom_base_url(self):
        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")
        assert client.base_url == "https://custom.api.com"

    def test_init_without_token(self):
        with pytest.raises(ValueError, match="non-empty string"):
            NeuwoEdgeClient(token="", base_url="https://custom.api.com")

    def test_init_without_base_url(self):
        with pytest.raises(ValueError, match="non-empty string"):
            NeuwoEdgeClient(token="test-token", base_url="")

    def test_init_strips_token_whitespace(self):
        client = NeuwoEdgeClient(
            token="  test-token  ", base_url="https://custom.api.com"
        )
        assert client.token == "test-token"

    def test_init_strips_base_url_slash(self):
        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com/")
        assert client.base_url == "https://custom.api.com"


class TestGetAiTopics:
    """Tests for get_ai_topics methods."""

    @patch("neuwo_api.edge_client.NeuwoEdgeClient._request")
    def test_get_ai_topics_success(self, mock_request, sample_get_ai_topics_response):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "{}"
        mock_request.return_value = mock_response

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")

        with patch(
            "neuwo_api.edge_client.parse_json_response",
            return_value=sample_get_ai_topics_response,
        ):
            result = client.get_ai_topics(url="https://example.com/article")

        assert len(result.tags) == 1
        assert result.tags[0].value == "Domestic Animals and Pets"
        mock_request.assert_called_once()

    def test_get_ai_topics_invalid_url(self):
        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")
        with pytest.raises(ValidationError):
            client.get_ai_topics(url="not-a-url")

    @patch("neuwo_api.edge_client.NeuwoEdgeClient._request")
    def test_get_ai_topics_with_origin(
        self, mock_request, sample_get_ai_topics_response
    ):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "{}"
        mock_request.return_value = mock_response

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")

        with patch(
            "neuwo_api.edge_client.parse_json_response",
            return_value=sample_get_ai_topics_response,
        ):
            client.get_ai_topics(
                url="https://example.com/article", origin="https://mysite.com"
            )

        call_args = mock_request.call_args
        assert call_args[1]["headers"]["Origin"] == "https://mysite.com"

    @patch("neuwo_api.edge_client.NeuwoEdgeClient._request")
    def test_get_ai_topics_raw(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")
        result = client.get_ai_topics_raw(url="https://example.com/article")

        assert result == mock_response

        # Check that URL param was passed
        call_args = mock_request.call_args
        assert call_args[1]["params"]["url"] == "https://example.com/article"


class TestGetAiTopicsWait:
    """Tests for get_ai_topics_wait method."""

    @patch("neuwo_api.edge_client.NeuwoEdgeClient.get_ai_topics")
    @patch("time.sleep")
    def test_get_ai_topics_wait_immediate_success(
        self, mock_sleep, mock_get, sample_get_ai_topics_response
    ):
        # Setup: immediate success
        from neuwo_api.models import GetAiTopicsResponse

        mock_get.return_value = GetAiTopicsResponse.from_dict(
            sample_get_ai_topics_response
        )

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")
        result = client.get_ai_topics_wait(url="https://example.com/article")

        assert len(result.tags) == 1
        # Should sleep once for initial_delay
        assert mock_sleep.call_count == 1
        # get_ai_topics should be called once
        assert mock_get.call_count == 1

    @patch("neuwo_api.edge_client.NeuwoEdgeClient.get_ai_topics")
    @patch("time.sleep")
    def test_get_ai_topics_wait_retry_then_success(
        self, mock_sleep, mock_get, sample_get_ai_topics_response
    ):
        # Setup: fail twice, then succeed
        from neuwo_api.models import GetAiTopicsResponse

        mock_get.side_effect = [
            NoDataAvailableError("No data yet available"),
            NoDataAvailableError("No data yet available"),
            GetAiTopicsResponse.from_dict(sample_get_ai_topics_response),
        ]

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")
        result = client.get_ai_topics_wait(url="https://example.com/article")

        assert len(result.tags) == 1
        # Should call get_ai_topics 3 times
        assert mock_get.call_count == 3
        # Should sleep: 1 initial + 2 retries
        assert mock_sleep.call_count == 3

    @patch("neuwo_api.edge_client.NeuwoEdgeClient.get_ai_topics")
    @patch("time.sleep")
    def test_get_ai_topics_wait_max_retries(self, mock_sleep, mock_get):
        # Setup: always fail
        mock_get.side_effect = NoDataAvailableError("No data yet available")

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")

        with pytest.raises(NoDataAvailableError, match="after 11 attempts"):
            client.get_ai_topics_wait(
                url="https://example.com/article", max_retries=10, retry_interval=1
            )

        # Should call get_ai_topics max_retries + 1 times
        assert mock_get.call_count == 11

    @patch("neuwo_api.edge_client.NeuwoEdgeClient.get_ai_topics")
    @patch("time.sleep")
    def test_get_ai_topics_wait_content_error_no_retry(self, mock_sleep, mock_get):
        # Setup: permanent error
        mock_get.side_effect = ContentNotAvailableError(url="https://example.com")

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")

        with pytest.raises(ContentNotAvailableError):
            client.get_ai_topics_wait(url="https://example.com/article")

        # Should only try once (no retries for permanent errors)
        assert mock_get.call_count == 1

    @patch("neuwo_api.edge_client.NeuwoEdgeClient.get_ai_topics")
    @patch("time.sleep")
    def test_get_ai_topics_wait_custom_intervals(
        self, mock_sleep, mock_get, sample_get_ai_topics_response
    ):
        from neuwo_api.models import GetAiTopicsResponse

        mock_get.return_value = GetAiTopicsResponse.from_dict(
            sample_get_ai_topics_response
        )

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")
        client.get_ai_topics_wait(
            url="https://example.com/article",
            max_retries=5,
            retry_interval=10,
            initial_delay=5,
        )

        # Check initial delay
        assert mock_sleep.call_args_list[0][0][0] == 5


class TestGetAiTopicsList:
    """Tests for get_ai_topics_list methods."""

    @patch("neuwo_api.edge_client.NeuwoEdgeClient._request")
    def test_get_ai_topics_list_success(
        self, mock_request, sample_get_ai_topics_response
    ):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "[]"
        mock_request.return_value = mock_response

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")

        response_with_url = {
            **sample_get_ai_topics_response,
            "url": "https://example.com",
        }

        with patch(
            "neuwo_api.edge_client.parse_json_response",
            return_value=[response_with_url],
        ):
            result = client.get_ai_topics_list(urls=["https://example.com"])

        assert len(result) == 1
        assert result[0].url == "https://example.com"

    @patch("neuwo_api.edge_client.NeuwoEdgeClient._request")
    def test_get_ai_topics_list_with_error(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "[]"
        mock_request.return_value = mock_response

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")

        error_response = [
            {"error": "Tagging not created", "url": "https://example.com"}
        ]

        with patch(
            "neuwo_api.edge_client.parse_json_response", return_value=error_response
        ):
            with pytest.raises(ContentNotAvailableError, match="Tagging not created"):
                client.get_ai_topics_list(urls=["https://example.com"])

    @patch("neuwo_api.edge_client.NeuwoEdgeClient._request")
    def test_get_ai_topics_list_raw(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")
        result = client.get_ai_topics_list_raw(urls=["https://example.com"])

        assert result == mock_response

        # Check that file was uploaded
        call_args = mock_request.call_args
        assert "files" in call_args[1]


class TestGetSimilar:
    """Tests for get_similar methods."""

    @patch("neuwo_api.edge_client.NeuwoEdgeClient._request")
    def test_get_similar_success(self, mock_request, sample_similar_article_data):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "[]"
        mock_request.return_value = mock_response

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")

        with patch(
            "neuwo_api.edge_client.parse_json_response",
            return_value=[sample_similar_article_data],
        ):
            result = client.get_similar(document_url="https://example.com/article")

        assert len(result) == 1
        assert result[0].article_id == "record_id_1"

    def test_get_similar_invalid_url(self):
        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")
        with pytest.raises(ValidationError):
            client.get_similar(document_url="not-a-url")

    @patch("neuwo_api.edge_client.NeuwoEdgeClient._request")
    def test_get_similar_with_filters(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")

        with patch("neuwo_api.edge_client.parse_json_response", return_value=[]):
            client.get_similar(
                document_url="https://example.com/article",
                max_rows=10,
                past_days=30,
                publication_ids=["pub1", "pub2"],
            )

        call_args = mock_request.call_args
        assert call_args[1]["params"]["document_url"] == "https://example.com/article"
        assert call_args[1]["params"]["max_rows"] == 10
        assert call_args[1]["params"]["past_days"] == 30
        assert call_args[1]["params"]["publicationid"] == ["pub1", "pub2"]

    @patch("neuwo_api.edge_client.NeuwoEdgeClient._request")
    def test_get_similar_raw(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")
        result = client.get_similar_raw(document_url="https://example.com/article")

        assert result == mock_response


class TestRequestWithOrigin:
    """Tests for _request method with origin header."""

    @patch("neuwo_api.edge_client.RequestHandler.request")
    def test_request_uses_default_origin(self, mock_handler_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_handler_request.return_value = mock_response

        client = NeuwoEdgeClient(
            token="test-token",
            base_url="https://custom.api.com",
            default_origin="https://default.com",
        )
        client._request("GET", "/test")

        call_args = mock_handler_request.call_args
        assert call_args[1]["headers"]["Origin"] == "https://default.com"

    @patch("neuwo_api.edge_client.RequestHandler.request")
    def test_request_overrides_origin(self, mock_handler_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_handler_request.return_value = mock_response

        client = NeuwoEdgeClient(
            token="test-token",
            base_url="https://custom.api.com",
            default_origin="https://default.com",
        )
        client._request("GET", "/test", headers={"Origin": "https://override.com"})

        call_args = mock_handler_request.call_args
        assert call_args[1]["headers"]["Origin"] == "https://override.com"

    @patch("neuwo_api.edge_client.RequestHandler.request")
    def test_request_no_origin_when_not_configured(self, mock_handler_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_handler_request.return_value = mock_response

        client = NeuwoEdgeClient(token="test-token", base_url="https://custom.api.com")
        client._request("GET", "/test")

        call_args = mock_handler_request.call_args
        # Should not add Origin header if not configured
        if call_args[1].get("headers"):
            assert "Origin" not in call_args[1]["headers"]
