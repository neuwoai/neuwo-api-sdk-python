"""
Unit tests for Neuwo API exceptions.
"""

from neuwo_api.exceptions import (
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


class TestNeuwoAPIError:
    """Tests for base NeuwoAPIError."""

    def test_basic_error(self):
        error = NeuwoAPIError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"
        assert error.status_code is None
        assert error.response_data == {}

    def test_error_with_status_code(self):
        error = NeuwoAPIError("Test error", status_code=400)
        assert str(error) == "[400] Test error"
        assert error.status_code == 400

    def test_error_with_response_data(self):
        response_data = {"detail": "Additional info"}
        error = NeuwoAPIError("Test error", response_data=response_data)
        assert error.response_data == response_data


class TestAuthenticationError:
    """Tests for AuthenticationError."""

    def test_default_message(self):
        error = AuthenticationError()
        assert "Unauthorized" in str(error)
        assert error.status_code == 401

    def test_custom_message(self):
        error = AuthenticationError("Invalid token")
        assert str(error) == "[401] Invalid token"


class TestForbiddenError:
    """Tests for ForbiddenError."""

    def test_default_message(self):
        error = ForbiddenError()
        assert "Forbidden" in str(error)
        assert error.status_code == 403


class TestNotFoundError:
    """Tests for NotFoundError."""

    def test_default_message(self):
        error = NotFoundError()
        assert "not found" in str(error).lower()
        assert error.status_code == 404


class TestValidationError:
    """Tests for ValidationError."""

    def test_basic_validation_error(self):
        error = ValidationError("Invalid input")
        assert str(error) == "[422] Invalid input"
        assert error.status_code == 422
        assert error.validation_details == []

    def test_validation_error_with_details(self):
        details = [
            {
                "loc": ["body", "content"],
                "msg": "field required",
                "type": "value_error.missing",
            }
        ]
        error = ValidationError("Validation failed", validation_details=details)
        assert error.validation_details == details
        error_str = str(error)
        assert "Validation failed" in error_str
        assert "field required" in error_str


class TestBadRequestError:
    """Tests for BadRequestError."""

    def test_default_message(self):
        error = BadRequestError()
        assert error.status_code == 400


class TestRateLimitError:
    """Tests for RateLimitError."""

    def test_default_message(self):
        error = RateLimitError()
        assert "Rate limit" in str(error)
        assert error.status_code == 429
        assert error.retry_after is None

    def test_with_retry_after(self):
        error = RateLimitError(retry_after=60)
        assert error.retry_after == 60


class TestServerError:
    """Tests for ServerError."""

    def test_default_status_code(self):
        error = ServerError()
        assert error.status_code == 500

    def test_custom_status_code(self):
        error = ServerError(status_code=503)
        assert error.status_code == 503


class TestNetworkError:
    """Tests for NetworkError."""

    def test_basic_network_error(self):
        error = NetworkError("Connection failed")
        assert str(error) == "Connection failed"
        assert error.__cause__ is None

    def test_network_error_with_original(self):
        original = Exception("Socket timeout")
        error = NetworkError("Connection failed", original_error=original)
        assert str(error) == "Connection failed"
        assert error.__cause__ == original
        assert error.__cause__.args[0] == "Socket timeout"


class TestContentNotAvailableError:
    """Tests for ContentNotAvailableError."""

    def test_default_message(self):
        error = ContentNotAvailableError()
        assert "could not be analyzed" in str(error).lower()

    def test_with_url(self):
        error = ContentNotAvailableError(url="https://example.com")
        assert "https://example.com" in str(error)
        assert error.url == "https://example.com"

    def test_with_custom_message(self):
        error = ContentNotAvailableError(message="Page unavailable")
        assert str(error) == "Page unavailable"


class TestNoDataAvailableError:
    """Tests for NoDataAvailableError."""

    def test_default_message(self):
        error = NoDataAvailableError()
        assert "No data yet available" in str(error)
        assert error.status_code == 404

    def test_custom_message(self):
        error = NoDataAvailableError("Still processing")
        assert str(error) == "[404] Still processing"

    def test_inherits_from_not_found_error(self):
        error = NoDataAvailableError()
        assert isinstance(error, NotFoundError)
        assert isinstance(error, NeuwoAPIError)
