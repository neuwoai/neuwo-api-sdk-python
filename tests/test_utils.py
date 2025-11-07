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
    RateLimitError,
    ServerError,
    ValidationError,
)
from neuwo_api.utils import (
    RequestHandler,
    parse_json_response,
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
        mock_response = Mock()
        mock_response.text = '{"key": "value"}'
        result = parse_json_response(mock_response)
        assert result == {"key": "value"}

    def test_json_with_error_field(self):
        mock_response = Mock()
        mock_response.text = '{"error": "Tagging not created", "url": "https://example.com"}'
        with pytest.raises(ContentNotAvailableError, match="Tagging not created"):
            parse_json_response(mock_response)

    def test_invalid_json(self):
        mock_response = Mock()
        mock_response.text = "not json"
        with pytest.raises(NeuwoAPIError, match="Invalid JSON"):
            parse_json_response(mock_response)


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

    # Initialization tests
    def test_init_basic(self):
        """Test basic initialization."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        assert handler.token == "test-token"
        assert handler.base_url == "https://api.test.com"
        assert handler.timeout == 60

    def test_init_custom_timeout(self):
        """Test initialization with custom timeout."""
        handler = RequestHandler(
            token="test-token", base_url="https://api.test.com", timeout=120
        )
        assert handler.timeout == 120

    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is removed from base_url."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com/")
        assert handler.base_url == "https://api.test.com"

    # _encode_value tests
    def test_encode_value_string(self):
        """Test encoding string values."""
        assert RequestHandler._encode_value("test") == "test"

    def test_encode_value_number(self):
        """Test encoding number values."""
        assert RequestHandler._encode_value(123) == "123"
        assert RequestHandler._encode_value(45.67) == "45.67"

    def test_encode_value_boolean_true(self):
        """Test encoding True value."""
        assert RequestHandler._encode_value(True) == "true"

    def test_encode_value_boolean_false(self):
        """Test encoding False value."""
        assert RequestHandler._encode_value(False) == "false"

    # encode_form_data tests
    def test_encode_form_data_simple(self):
        """Test encoding simple form data."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        data = {"key": "value"}
        result = handler.encode_form_data(data)
        assert result == "key=value"

    def test_encode_form_data_multiple_fields(self):
        """Test encoding multiple form fields."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        data = {"key1": "value1", "key2": "value2"}
        result = handler.encode_form_data(data)
        assert "key1=value1" in result
        assert "key2=value2" in result

    def test_encode_form_data_boolean(self):
        """Test encoding boolean values."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        data = {"flag": True, "disabled": False}
        result = handler.encode_form_data(data)
        assert "flag=true" in result
        assert "disabled=false" in result

    def test_encode_form_data_list_values(self):
        """Test encoding list values."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        data = {"tags": ["tag1", "tag2"]}
        result = handler.encode_form_data(data)
        assert "tags=tag1" in result
        assert "tags=tag2" in result

    def test_encode_form_data_none_values_filtered(self):
        """Test that None values are filtered out."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        data = {"key1": "value1", "key2": None}
        result = handler.encode_form_data(data)
        assert "key1=value1" in result
        assert "key2" not in result

    def test_encode_form_data_none_in_list_filtered(self):
        """Test that None values in lists are filtered out."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        data = {"tags": ["tag1", None, "tag2"]}
        result = handler.encode_form_data(data)
        assert "tags=tag1" in result
        assert "tags=tag2" in result
        # Should only have two tags parameters
        assert result.count("tags=") == 2

    def test_encode_form_data_empty_dict(self):
        """Test encoding empty dictionary."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        data = {}
        result = handler.encode_form_data(data)
        assert result == ""

    # _build_url tests
    def test_build_url_simple(self):
        """Test URL building with simple parameters."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        url = handler._build_url("/test", {"key": "value"})
        assert "https://api.test.com/test" in url
        assert "token=test-token" in url
        assert "key=value" in url

    def test_build_url_with_list_params(self):
        """Test URL building with list parameters."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        url = handler._build_url("/test", {"ids": ["id1", "id2"]})
        assert "ids=id1" in url
        assert "ids=id2" in url
        assert "token=test-token" in url

    def test_build_url_filters_none_values(self):
        """Test that None values are filtered out."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        url = handler._build_url("/test", {"key1": "value1", "key2": None})
        assert "key1=value1" in url
        assert "key2" not in url

    def test_build_url_encodes_special_chars(self):
        """Test URL encoding of special characters."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        url = handler._build_url("/test", {"key": "value with spaces"})
        assert "value%20with%20spaces" in url

    def test_build_url_no_params(self):
        """Test URL building without additional parameters."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        url = handler._build_url("/test")
        assert "https://api.test.com/test" in url
        assert "token=test-token" in url

    def test_build_url_endpoint_without_slash(self):
        """Test URL building when endpoint doesn't start with /."""
        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        url = handler._build_url("test", {"key": "value"})
        assert "https://api.test.com/test" in url

    def test_build_url_base_with_path(self):
        """Test URL building when base URL has a path."""
        handler = RequestHandler(
            token="test-token", base_url="https://api.test.com/v1"
        )
        url = handler._build_url("/endpoint")
        assert "https://api.test.com/v1/endpoint" in url

    def test_build_url_encodes_token(self):
        """Test that token with special characters is encoded."""
        handler = RequestHandler(
            token="test token+special", base_url="https://api.test.com"
        )
        url = handler._build_url("/test")
        assert "test%20token%2Bspecial" in url

    # request method tests
    @patch("neuwo_api.utils.requests.request")
    def test_request_get_success(self, mock_request):
        """Test successful GET request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"result": "success"}'
        mock_request.return_value = mock_response

        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        response = handler.request("GET", "/test", params={"key": "value"})

        assert response.status_code == 200
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        called_url = call_args[1]["url"]
        assert "token=test-token" in called_url
        assert "key=value" in called_url
        assert "/test" in called_url
        assert call_args[1]["method"] == "GET"

    @patch("neuwo_api.utils.requests.request")
    def test_request_post_with_form_data(self, mock_request):
        """Test POST request with form data."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        handler.request("POST", "/test", data={"content": "test", "flag": True})

        call_args = mock_request.call_args
        assert "content=test" in call_args[1]["data"]
        assert "flag=true" in call_args[1]["data"]
        assert call_args[1]["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
        assert call_args[1]["method"] == "POST"

    @patch("neuwo_api.utils.requests.request")
    def test_request_with_custom_headers(self, mock_request):
        """Test request with custom headers."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        custom_headers = {"X-Custom-Header": "custom-value"}
        handler.request("GET", "/test", headers=custom_headers)

        call_args = mock_request.call_args
        assert call_args[1]["headers"]["X-Custom-Header"] == "custom-value"

    @patch("neuwo_api.utils.requests.request")
    def test_request_custom_content_type(self, mock_request):
        """Test that custom Content-Type is preserved."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        headers = {"Content-Type": "application/json"}
        handler.request("POST", "/test", data={"key": "value"}, headers=headers)

        call_args = mock_request.call_args
        # Custom Content-Type should be preserved
        assert call_args[1]["headers"]["Content-Type"] == "application/json"

    @patch("neuwo_api.utils.requests.request")
    def test_request_put_method(self, mock_request):
        """Test PUT request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        handler = RequestHandler(token="test-token", base_url="https://api.test.com")
        handler.request("PUT", "/test", data={"key": "value"})

        call_args = mock_request.call_args
        assert call_args[1]["method"] == "PUT"

    @patch("neuwo_api.utils.requests.request")
    def test_request_timeout_applied(self, mock_request):
        """Test that timeout is applied to request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        handler = RequestHandler(
            token="test-token", base_url="https://api.test.com", timeout=30
        )
        handler.request("GET", "/test")

        call_args = mock_request.call_args
        assert call_args[1]["timeout"] == 30

    @patch("neuwo_api.utils.requests.request")
    def test_request_error_response_handling(self, mock_request):
        """Test error response handling."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"message": "Unauthorised"}
        mock_request.return_value = mock_response

        handler = RequestHandler(token="test-token", base_url="https://api.test.com")

        with pytest.raises(AuthenticationError):
            handler.request("GET", "/test")

    @patch("neuwo_api.utils.requests.request")
    def test_request_timeout_error(self, mock_request):
        """Test timeout exception handling."""
        import requests

        mock_request.side_effect = requests.exceptions.Timeout()

        handler = RequestHandler(
            token="test-token", base_url="https://api.test.com", timeout=30
        )

        from neuwo_api.exceptions import NetworkError

        with pytest.raises(NetworkError, match="timeout"):
            handler.request("GET", "/test")

    @patch("neuwo_api.utils.requests.request")
    def test_request_connection_error(self, mock_request):
        """Test connection error handling."""
        import requests

        mock_request.side_effect = requests.exceptions.ConnectionError()

        handler = RequestHandler(token="test-token", base_url="https://api.test.com")

        from neuwo_api.exceptions import NetworkError

        with pytest.raises(NetworkError, match="connect"):
            handler.request("GET", "/test")

    @patch("neuwo_api.utils.requests.request")
    def test_request_generic_exception(self, mock_request):
        """Test generic request exception handling."""
        import requests

        mock_request.side_effect = requests.exceptions.RequestException("Generic error")

        handler = RequestHandler(token="test-token", base_url="https://api.test.com")

        from neuwo_api.exceptions import NetworkError

        with pytest.raises(NetworkError, match="Request failed"):
            handler.request("GET", "/test")

    class TestHandleApiError:
        """Tests for handle_api_error static method."""

        @staticmethod
        def create_mock_response(status_code: int, json_data: dict, headers: dict = None):
            """Helper to create a mock response."""
            mock_response = Mock()
            mock_response.status_code = status_code
            mock_response.json.return_value = json_data
            mock_response.headers = headers or {}
            return mock_response

        def test_400_error(self):
            response = self.create_mock_response(400, {"message": "Bad request"})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, BadRequestError)
            assert "Bad request" in str(error)

        def test_401_error(self):
            response = self.create_mock_response(401, {"message": "Unauthorised"})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, AuthenticationError)

        def test_403_error(self):
            response = self.create_mock_response(403, {"message": "Forbidden"})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, ForbiddenError)

        def test_404_error(self):
            response = self.create_mock_response(404, {"detail": "Not found"})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, NotFoundError)

        def test_404_no_data_available(self):
            response = self.create_mock_response(404, {"detail": "No data yet available"})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, NoDataAvailableError)

        def test_422_error(self):
            response = self.create_mock_response(422, {"detail": "Validation error"})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, ValidationError)

        def test_422_with_validation_details(self):
            details = [{"loc": ["body"], "msg": "required"}]
            response = self.create_mock_response(422, {"detail": details})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, ValidationError)
            assert error.validation_details == details

        def test_429_error(self):
            response = self.create_mock_response(429, {"message": "Rate limit exceeded"})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, RateLimitError)
            assert "Rate limit exceeded" in str(error)
            assert error.status_code == 429

        def test_429_error_with_retry_after_header(self):
            mock_response = Mock()
            mock_response.status_code = 429
            mock_response.json.return_value = {"message": "Too many requests"}
            mock_response.headers = {"Retry-After": "60"}

            error = RequestHandler.handle_api_error(mock_response)
            assert isinstance(error, RateLimitError)
            assert error.retry_after == 60
            assert "Too many requests" in str(error)

        def test_429_error_with_invalid_retry_after_header(self):
            mock_response = Mock()
            mock_response.status_code = 429
            mock_response.json.return_value = {"message": "Rate limit exceeded"}
            mock_response.headers = {"Retry-After": "invalid"}

            error = RequestHandler.handle_api_error(mock_response)
            assert isinstance(error, RateLimitError)
            assert error.retry_after is None

        def test_429_error_without_retry_after_header(self):
            response = self.create_mock_response(429, {"message": "Rate limit exceeded"})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, RateLimitError)
            assert error.retry_after is None

        def test_500_error(self):
            response = self.create_mock_response(500, {"message": "Server error"})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, ServerError)
            assert error.status_code == 500

        def test_503_error(self):
            response = self.create_mock_response(503, {"message": "Service unavailable"})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, ServerError)
            assert error.status_code == 503

        def test_error_with_detail_field(self):
            response = self.create_mock_response(400, {"detail": "Invalid parameter"})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, BadRequestError)
            assert "Invalid parameter" in str(error)

        def test_error_with_error_field(self):
            response = self.create_mock_response(400, {"error": "Something went wrong"})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, BadRequestError)
            assert "Something went wrong" in str(error)

        def test_error_with_no_json_response(self):
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.json.side_effect = Exception("Not JSON")
            mock_response.text = "Internal Server Error"

            error = RequestHandler.handle_api_error(mock_response)
            assert isinstance(error, ServerError)
            assert "Internal Server Error" in str(error)

        def test_unhandled_status_code(self):
            response = self.create_mock_response(418, {"message": "I'm a teapot"})
            error = RequestHandler.handle_api_error(response)
            assert isinstance(error, NeuwoAPIError)
            assert error.status_code == 418
            assert "I'm a teapot" in str(error)
