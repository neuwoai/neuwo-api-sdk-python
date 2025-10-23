# Neuwo API SDK Tests

This directory contains the test suite for the Neuwo API SDK.

## Test Structure

```
tests/
├── conftest.py              # Shared fixtures and test configuration
├── test_models.py           # Tests for data models
├── test_exceptions.py       # Tests for custom exceptions
├── test_utils.py            # Tests for utility functions
├── test_rest_client.py      # Tests for REST API client
├── test_edge_client.py      # Tests for EDGE API client
└── README.md               # This file
```

## Running Tests

### Install Test Dependencies

First, install the package with test dependencies:

```bash
pip install -e ".[test]"
```

Or install all development dependencies:

```bash
pip install -e ".[dev]"
```

### Run All Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=neuwo_api --cov-report=html --cov-report=term
```

### Run Specific Test Files

```bash
# Test only models
pytest tests/test_models.py

# Test only REST client
pytest tests/test_rest_client.py

# Test only EDGE client
pytest tests/test_edge_client.py
```

### Run Specific Test Classes or Methods

```bash
# Run a specific test class
pytest tests/test_models.py::TestTag

# Run a specific test method
pytest tests/test_models.py::TestTag::test_from_dict_without_parents

# Run tests matching a pattern
pytest -k "test_get_ai_topics"
```

### Coverage Reports

After running tests with coverage, open the HTML report:

```bash
# Generate and open coverage report
pytest --cov=neuwo_api --cov-report=html
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

## Test Categories

### Unit Tests

All tests in this directory are unit tests that use mocking to avoid making real API calls.

- **Models Tests**: Test data model serialization/deserialization
- **Exceptions Tests**: Test exception classes and error handling
- **Utils Tests**: Test utility functions like URL validation, parsing, etc.
- **Client Tests**: Test REST and EDGE client methods with mocked responses

### Writing New Tests

When adding new functionality:

1. Add test fixtures to `conftest.py` if needed
2. Create tests following the existing patterns
3. Use mocking to avoid real API calls
4. Test both success and error cases
5. Aim for high coverage (>90%)

Example test structure:

```python
class TestYourFeature:
    """Tests for your feature."""

    def test_success_case(self):
        # Test successful execution
        pass

    def test_error_case(self):
        # Test error handling
        with pytest.raises(SomeException):
            pass

    @patch('module.function')
    def test_with_mock(self, mock_func):
        # Test with mocked dependencies
        mock_func.return_value = "mocked"
        pass
```

## Continuous Integration

Tests are automatically run on:

- Every pull request
- Every commit to main branch
- Before publishing releases

## Test Requirements

- Python 3.8+
- pytest >= 7.0.0
- pytest-cov >= 4.0.0
- All dependencies in `requirements.txt`

## Troubleshooting

### Import Errors

If you get import errors, make sure the package is installed in development mode:

```bash
pip install -e .
```

### Mock Issues

If mocks aren't working correctly, check:

1. You're patching the correct import path
2. The patch decorator is applied correctly
3. Mock is configured before the test runs

### Fixture Issues

If fixtures aren't available:

1. Check they're defined in `conftest.py`
2. Check the fixture scope is correct
3. Ensure pytest can discover `conftest.py`
