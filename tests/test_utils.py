"""
Unit tests for Neuwo API utilities.
"""

from unittest.mock import Mock, patch

import pytest

from neuwo_api.exceptions import (
    AuthenticationError,
    BadRequestError,
    ContentNotAvailableError,
    ForbiddenError,
    NeuwoAPIError,
    NoDataAvailableError,
    NotFoundError,
    ValidationError,
)
from neuwo_api.utils import (
    RequestHandler,
    build_form_data,
    build_query_string,
    parse_json_response,
    parse_xml_response,
    prepare_url_list_file,
    sanitize_content,
    validate_url,
)


class TestValidateUrl:
    """Tests for validate_url function."""

    def test_valid_http_url(self):
        assert validate_url("http://example.com") is True

    def test_valid_https_url(self):
        assert validate_url("https://example.com/path") is True

    def test_empty_url(self):
        with pytest.raises(ValidationError, match="non-empty string"):
            validate_url("")

    def test_none_url(self):
        with pytest.raises(ValidationError, match="non-empty string"):
            validate_url(None)

    def test_invalid_scheme(self):
        with pytest.raises(ValidationError, match="http or https"):
            validate_url("ftp://example.com")

    def test_no_scheme(self):
        with pytest.raises(ValidationError, match="Invalid URL"):
            validate_url("example.com")

    def test_whitespace_stripped(self):
        assert validate_url("  https://example.com  ") is True


class TestParseJsonResponse:
    """Tests for parse_json_response function."""

    def test_valid_json(self):
        json_str = '{"key": "value"}'
        result = parse_json_response(json_str)
        assert result == {"key": "value"}

    def test_json_with_error_field(self):
        json_str = '{"error": "Tagging not created", "url": "https://example.com"}'
        with pytest.raises(ContentNotAvailableError, match="Tagging not created"):
            parse_json_response(json_str)

    def test_invalid_json(self):
        with pytest.raises(NeuwoAPIError, match="Invalid JSON"):
            parse_json_response("not json")


class TestParseXmlResponse:
    """Tests for parse_xml_response function."""

    def test_simple_xml(self):
        xml_str = "<rsp><headline>Test</headline></rsp>"
        result = parse_xml_response(xml_str)
        assert result["headline"] == "Test"

    def test_xml_with_multiple_same_tags(self):
        xml_str = "<rsp><headline>Test1</headline><headline>Test2</headline></rsp>"
        result = parse_xml_response(xml_str)
        assert isinstance(result["headline"], list)
        assert len(result["headline"]) == 2

    def test_invalid_xml(self):
        with pytest.raises(NeuwoAPIError, match="Invalid XML"):
            parse_xml_response("<invalid>")


class TestBuildQueryString:
    """Tests for build_query_string function."""

    def test_simple_params(self):
        params = {"key1": "value1", "key2": "value2"}
        result = build_query_string(params)
        assert "key1=value1" in result
        assert "key2=value2" in result

    def test_none_values_filtered(self):
        params = {"key1": "value1", "key2": None}
        result = build_query_string(params)
        assert "key1=value1" in result
        assert "key2" not in result

    def test_list_values(self):
        params = {"ids": ["id1", "id2"]}
        result = build_query_string(params)
        assert "ids=id1" in result
        assert "ids=id2" in result

    def test_url_encoding(self):
        params = {"key": "value with spaces"}
        result = build_query_string(params)
        assert "value%20with%20spaces" in result


class TestBuildFormData:
    """Tests for build_form_data function."""

    def test_simple_data(self):
        data = {"key": "value"}
        result = build_form_data(data)
        assert result == "key=value"

    def test_boolean_conversion(self):
        data = {"flag": True}
        result = build_form_data(data)
        assert result == "flag=true"

    def test_list_values(self):
        data = {"tags": ["tag1", "tag2"]}
        result = build_form_data(data)
        assert "tags=tag1" in result
        assert "tags=tag2" in result

    def test_none_values_filtered(self):
        data = {"key1": "value1", "key2": None}
        result = build_form_data(data)
        assert "key1=value1" in result
        assert "key2" not in result


class TestPrepareUrlListFile:
    """Tests for prepare_url_list_file function."""

    def test_valid_urls(self):
        urls = ["https://example.com", "https://test.com"]
        result = prepare_url_list_file(urls)
        assert result == b"https://example.com,https://test.com"

    def test_invalid_url_raises_error(self):
        urls = ["https://example.com", "not_a_url"]
        with pytest.raises(ValidationError):
            prepare_url_list_file(urls)


class TestSanitizeContent:
    """Tests for sanitize_content function."""

    def test_valid_content(self):
        content = "  This is valid content  "
        result = sanitize_content(content)
        assert result == "This is valid content"

    def test_empty_content(self):
        with pytest.raises(ValidationError, match="non-empty string"):
            sanitize_content("")

    def test_whitespace_only(self):
        with pytest.raises(ValidationError, match="whitespace"):
            sanitize_content("   ")

    def test_none_content(self):
        with pytest.raises(ValidationError, match="non-empty string"):
            sanitize_content(None)


class TestRequestHandler:
    """Tests for RequestHandler class."""

    @patch("neuwo_api.utils.requests.request")
    def test_successful_request(self, mock_request):
        # Setup mock
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"result": "success"}'
        mock_request.return_value = mock_response

        # Create handler and make request
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        response = handler.request("GET", "/test", params={"key": "value"})

        # Assertions
        assert response.status_code == 200
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        assert call_args[1]["params"]["token"] == "test-token"
        assert call_args[1]["params"]["key"] == "value"

    @patch("neuwo_api.utils.requests.request")
    def test_request_with_form_data(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        handler.request("POST", "/test", data={"content": "test"})

        call_args = mock_request.call_args
        assert "content=test" in call_args[1]["data"]

    @patch("neuwo_api.utils.requests.request")
    def test_request_with_files(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        files = {"file": ("test.txt", b"content")}
        handler.request("POST", "/test", files=files)

        call_args = mock_request.call_args
        assert call_args[1]["files"] == files

    @patch("neuwo_api.utils.requests.request")
    def test_error_response_handling(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"message": "Unauthorized"}
        mock_request.return_value = mock_response

        handler = RequestHandler(token="test-token", base_url="https://api.test.com")

        with pytest.raises(AuthenticationError):
            handler.request("GET", "/test")

    @patch("neuwo_api.utils.requests.request")
    def test_timeout_error(self, mock_request):
        import requests

        mock_request.side_effect = requests.exceptions.Timeout()

        handler = RequestHandler(
            token="test-token", base_url="https://api.test.com", timeout=30
        )

        from neuwo_api.exceptions import NetworkError

        with pytest.raises(NetworkError, match="timeout"):
            handler.request("GET", "/test")

    @patch("neuwo_api.utils.requests.request")
    def test_connection_error(self, mock_request):
        import requests

        mock_request.side_effect = requests.exceptions.ConnectionError()

        handler = RequestHandler(token="test-token", base_url="https://api.test.com")

        from neuwo_api.exceptions import NetworkError

        with pytest.raises(NetworkError, match="connect"):
            handler.request("GET", "/test")

    class TestHandleApiError:
        """Tests for handle_api_error static method."""

        def test_400_error(self):
            error = RequestHandler.handle_api_error(400, {"message": "Bad request"})
            assert isinstance(error, BadRequestError)
            assert "Bad request" in str(error)

        def test_401_error(self):
            error = RequestHandler.handle_api_error(401, {"message": "Unauthorized"})
            assert isinstance(error, AuthenticationError)

        def test_403_error(self):
            error = RequestHandler.handle_api_error(403, {"message": "Forbidden"})
            assert isinstance(error, ForbiddenError)

        def test_404_error(self):
            error = RequestHandler.handle_api_error(404, {"detail": "Not found"})
            assert isinstance(error, NotFoundError)

        def test_404_no_data_available(self):
            error = RequestHandler.handle_api_error(
                404, {"detail": "No data yet available"}
            )
            assert isinstance(error, NoDataAvailableError)

        def test_422_error(self):
            error = RequestHandler.handle_api_error(422, {"detail": "Validation error"})
            assert isinstance(error, ValidationError)

        def test_422_with_validation_details(self):
            details = [{"loc": ["body"], "msg": "required"}]
            error = RequestHandler.handle_api_error(422, {"detail": details})
            assert isinstance(error, ValidationError)
            assert error.validation_details == details

        def test_500_error(self):
            error = RequestHandler.handle_api_error(500, {"message": "Server error"})
            assert error.status_code == 500
