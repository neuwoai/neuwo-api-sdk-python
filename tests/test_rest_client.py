"""
Unit tests for Neuwo REST API client.
"""

from datetime import date
from unittest.mock import Mock, patch

import pytest

from neuwo_api.exceptions import ValidationError
from neuwo_api.rest_client import NeuwoRestClient


class TestNeuwoRestClientInit:
    """Tests for NeuwoRestClient initialization."""

    def test_init_with_token(self):
        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")
        assert client.token == "test-token"
        assert client.base_url == "https://custom.api.com"
        assert client.timeout == 60

    def test_init_with_custom_base_url(self):
        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")
        assert client.base_url == "https://custom.api.com"

    def test_init_with_custom_timeout(self):
        client = NeuwoRestClient(
            token="test-token", base_url="https://custom.api.com", timeout=120
        )
        assert client.timeout == 120

    def test_init_without_token(self):
        with pytest.raises(ValueError, match="non-empty string"):
            NeuwoRestClient(token="", base_url="https://custom.api.com")

    def test_init_without_base_url(self):
        with pytest.raises(ValueError, match="non-empty string"):
            NeuwoRestClient(token="test-token", base_url="")

    def test_init_strips_token_whitespace(self):
        client = NeuwoRestClient(
            token="  test-token  ", base_url="https://custom.api.com"
        )
        assert client.token == "test-token"

    def test_init_strips_base_url_slash(self):
        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com/")
        assert client.base_url == "https://custom.api.com"


class TestGetAiTopics:
    """Tests for get_ai_topics methods."""

    @patch("neuwo_api.rest_client.NeuwoRestClient._request")
    def test_get_ai_topics_success(self, mock_request, sample_get_ai_topics_response):
        # Setup mock
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = str(sample_get_ai_topics_response).replace("'", '"')
        mock_request.return_value = mock_response

        # Create client and call method
        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")

        with patch(
            "neuwo_api.rest_client.parse_json_response",
            return_value=sample_get_ai_topics_response,
        ):
            result = client.get_ai_topics(content="Test content")

        # Assertions
        assert len(result.tags) == 1
        assert result.tags[0].value == "Domestic Animals and Pets"
        mock_request.assert_called_once()

    @patch("neuwo_api.rest_client.NeuwoRestClient._request")
    def test_get_ai_topics_with_all_params(
        self, mock_request, sample_get_ai_topics_response
    ):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "{}"
        mock_request.return_value = mock_response

        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")

        with patch(
            "neuwo_api.rest_client.parse_json_response",
            return_value=sample_get_ai_topics_response,
        ):
            _ = client.get_ai_topics(
                content="Test content",
                document_id="doc123",
                lang="en",
                publication_id="pub1",
                headline="Test Headline",
                tag_limit=20,
                tag_min_score=0.2,
                marketing_limit=10,
                marketing_min_score=0.4,
                include_in_sim=False,
                article_url="https://example.com",
            )

        # Check that request was made with correct data
        call_args = mock_request.call_args
        assert call_args[1]["data"]["content"] == "Test content"
        assert call_args[1]["data"]["documentid"] == "doc123"
        assert call_args[1]["data"]["tag_limit"] == 20

    def test_get_ai_topics_empty_content(self):
        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")
        with pytest.raises(ValidationError, match="non-empty string"):
            client.get_ai_topics(content="")

    def test_get_ai_topics_whitespace_only(self):
        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")
        with pytest.raises(ValidationError, match="whitespace"):
            client.get_ai_topics(content="   ")

    @patch("neuwo_api.rest_client.NeuwoRestClient._request")
    def test_get_ai_topics_raw(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")
        result = client.get_ai_topics_raw(content="Test content")

        assert result == mock_response
        mock_request.assert_called_once()


class TestGetSimilar:
    """Tests for get_similar methods."""

    @patch("neuwo_api.rest_client.NeuwoRestClient._request")
    def test_get_similar_success(self, mock_request, sample_similar_article_data):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "[]"
        mock_request.return_value = mock_response

        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")

        with patch(
            "neuwo_api.rest_client.parse_json_response",
            return_value=[sample_similar_article_data],
        ):
            result = client.get_similar(document_id="doc123")

        assert len(result) == 1
        assert result[0].article_id == "record_id_1"
        mock_request.assert_called_once()

    @patch("neuwo_api.rest_client.NeuwoRestClient._request")
    def test_get_similar_with_filters(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")

        with patch("neuwo_api.rest_client.parse_json_response", return_value=[]):
            client.get_similar(
                document_id="doc123",
                max_rows=10,
                past_days=30,
                publication_ids=["pub1", "pub2"],
            )

        call_args = mock_request.call_args
        assert call_args[1]["params"]["documentid"] == "doc123"
        assert call_args[1]["params"]["max_rows"] == 10
        assert call_args[1]["params"]["past_days"] == 30
        assert call_args[1]["params"]["publicationid"] == ["pub1", "pub2"]

    @patch("neuwo_api.rest_client.NeuwoRestClient._request")
    def test_get_similar_raw(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")
        result = client.get_similar_raw(document_id="doc123")

        assert result == mock_response


class TestUpdateArticle:
    """Tests for update_article methods."""

    @patch("neuwo_api.rest_client.NeuwoRestClient._request")
    def test_update_article_success(self, mock_request, sample_article_data):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "{}"
        mock_request.return_value = mock_response

        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")

        with patch(
            "neuwo_api.rest_client.parse_json_response",
            return_value=sample_article_data,
        ):
            result = client.update_article(
                document_id="doc123",
                headline="Updated Headline",
                published=date(2024, 1, 15),
            )

        assert result.article_id == "record_id_123"
        assert result.headline == "News"

        # Check endpoint
        call_kwargs = mock_request.call_args[1]
        assert "/UpdateArticle/doc123" in call_kwargs.get("endpoint", "")

    @patch("neuwo_api.rest_client.NeuwoRestClient._request")
    def test_update_article_all_fields(self, mock_request, sample_article_data):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")

        with patch(
            "neuwo_api.rest_client.parse_json_response",
            return_value=sample_article_data,
        ):
            client.update_article(
                document_id="doc123",
                published=date(2024, 1, 15),
                headline="Test",
                writer="Author",
                category="News",
                content="Content",
                summary="Summary",
                publication_id="pub1",
                article_url="https://example.com",
                include_in_sim=False,
            )

        call_args = mock_request.call_args
        data = call_args[1]["data"]
        assert data["headline"] == "Test"
        assert data["writer"] == "Author"
        assert data["include_in_sim"] is False


class TestTrainAiTopics:
    """Tests for train_ai_topics methods."""

    @patch("neuwo_api.rest_client.NeuwoRestClient._request")
    def test_train_ai_topics_success(self, mock_request, sample_training_tag_data):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "[]"
        mock_request.return_value = mock_response

        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")

        with patch(
            "neuwo_api.rest_client.parse_json_response",
            return_value=[sample_training_tag_data],
        ):
            result = client.train_ai_topics(document_id="doc123", tags=["tag1", "tag2"])

        assert len(result) == 1
        assert result[0].article_id == "record_id_1"

    def test_train_ai_topics_empty_tags(self):
        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")
        with pytest.raises(ValidationError, match="TrainingTag values"):
            client.train_ai_topics(document_id="doc123", tags=[])

    def test_train_ai_topics_none_tags(self):
        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")
        with pytest.raises(ValidationError):
            client.train_ai_topics(document_id="doc123", tags=None)

    @patch("neuwo_api.rest_client.NeuwoRestClient._request")
    def test_train_ai_topics_raw(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")
        result = client.train_ai_topics_raw(document_id="doc123", tags=["tag1", "tag2"])

        assert result == mock_response
        call_args = mock_request.call_args
        assert call_args[1]["data"]["tags"] == ["tag1", "tag2"]


class TestParseResponse:
    """Tests for _parse_response method."""

    def test_parse_json_response(self):
        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")
        mock_response = Mock()
        mock_response.text = '{"key": "value"}'

        with patch(
            "neuwo_api.rest_client.parse_json_response", return_value={"key": "value"}
        ):
            result = client._parse_response(mock_response, "json")

        assert result == {"key": "value"}

    def test_parse_xml_response(self):
        client = NeuwoRestClient(token="test-token", base_url="https://custom.api.com")
        mock_response = Mock()
        mock_response.text = "<rsp><key>value</key></rsp>"

        with patch(
            "neuwo_api.rest_client.parse_xml_response", return_value={"key": "value"}
        ):
            result = client._parse_response(mock_response, "xml")

        assert result == {"key": "value"}
