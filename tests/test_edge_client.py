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
        client = NeuwoEdgeClient(
            token="test-token", base_url="https://custom.api.com"
        )
        assert client._request_handler.token == "test-token"
        assert client._request_handler.base_url == "https://custom.api.com"
        assert client._request_handler.timeout == 60
        assert client.default_origin is None

    def test_init_with_origin(self):
        client = NeuwoEdgeClient(
            token="test-token",
            base_url="https://custom.api.com",
            default_origin="https://example.com",
        )
        assert client.default_origin == "https://example.com"

    def test_init_with_custom_base_url(self):
        client = NeuwoEdgeClient(
            token="test-token", base_url="https://custom.api.com"
        )
        assert client._request_handler.base_url == "https://custom.api.com"

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
        assert client._request_handler.token == "test-token"

    def test_init_strips_base_url_slash(self):
        client = NeuwoEdgeClient(
            token="test-token", base_url="https://custom.api.com/"
        )
        assert client._request_handler.base_url == "https://custom.api.com"


class TestGetAiTopics:
    """Tests for get_ai_topics methods."""

    @patch("neuwo_api.utils.RequestHandler.request")
    def test_get_ai_topics_success(
        self, mock_request, sample_get_ai_topics_response
    ):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "{}"
        mock_request.return_value = mock_response

        client = NeuwoEdgeClient(
            token="test-token", base_url="https://custom.api.com"
        )

        with patch(
            "neuwo_api.edge_client.parse_json_response",
            return_value=sample_get_ai_topics_response,
        ):
            result = client.get_ai_topics(url="https://example.com/article")

        assert len(result.tags) == 1
        assert result.tags[0].value == "Domestic Animals and Pets"
        mock_request.assert_called_once()

    def test_get_ai_topics_invalid_url(self):
        client = NeuwoEdgeClient(
            token="test-token", base_url="https://custom.api.com"
        )
        with pytest.raises(ValidationError):
            client.get_ai_topics(url="not-a-url")

    @patch("neuwo_api.utils.RequestHandler.request")
    def test_get_ai_topics_with_origin(
        self, mock_request, sample_get_ai_topics_response
    ):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "{}"
        mock_request.return_value = mock_response

        client = NeuwoEdgeClient(
            token="test-token", base_url="https://custom.api.com"
        )

        with patch(
            "neuwo_api.edge_client.parse_json_response",
            return_value=sample_get_ai_topics_response,
        ):
            client.get_ai_topics(
                url="https://example.com/article", origin="https://mysite.com"
            )

        call_args = mock_request.call_args
        assert call_args[1]["headers"]["Origin"] == "https://mysite.com"

    @patch("neuwo_api.utils.RequestHandler.request")
    def test_get_ai_topics_raw(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client = NeuwoEdgeClient(
            token="test-token", base_url="https://custom.api.com"
        )
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

        client = NeuwoEdgeClient(
            token="test-token", base_url="https://custom.api.com"
        )
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

        client = NeuwoEdgeClient(
            token="test-token", base_url="https://custom.api.com"
        )
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

        client = NeuwoEdgeClient(
            token="test-token", base_url="https://custom.api.com"
        )

        with pytest.raises(NoDataAvailableError, match="after 11 attempts"):
            client.get_ai_topics_wait(
                url="https://example.com/article",
                max_retries=10,
                retry_interval=1,
            )

        # Should call get_ai_topics max_retries + 1 times
        assert mock_get.call_count == 11

    @patch("neuwo_api.edge_client.NeuwoEdgeClient.get_ai_topics")
    @patch("time.sleep")
    def test_get_ai_topics_wait_content_error_no_retry(
        self, mock_sleep, mock_get
    ):
        # Setup: permanent error
        mock_get.side_effect = ContentNotAvailableError(
            url="https://example.com"
        )

        client = NeuwoEdgeClient(
            token="test-token", base_url="https://custom.api.com"
        )

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

        client = NeuwoEdgeClient(
            token="test-token", base_url="https://custom.api.com"
        )
        client.get_ai_topics_wait(
            url="https://example.com/article",
            max_retries=5,
            retry_interval=10,
            initial_delay=5,
        )

        # Check initial delay
        assert mock_sleep.call_args_list[0][0][0] == 5
