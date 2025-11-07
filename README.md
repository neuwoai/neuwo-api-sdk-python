# Neuwo API Python SDK

Python SDK client for the Neuwo content classification API.

[![PyPI version](https://badge.fury.io/py/neuwo-api.svg)](https://pypi.org/project/neuwo-api/)
[![Python versions](https://img.shields.io/pypi/pyversions/neuwo-api.svg)](https://pypi.org/project/neuwo-api/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Support

- **Neuwo**: [https://neuwo.ai](https://neuwo.ai)
- **Documentation**: [https://docs.neuwo.ai](https://docs.neuwo.ai)
- **Repository**: [GitHub](https://github.com/neuwoai/neuwo-api-sdk-python)
- **Issues**: [GitHub Issues](https://github.com/neuwoai/neuwo-api-sdk-python/issues)
- **Email Support**: [neuwo-helpdesk@neuwo.ai](mailto:neuwo-helpdesk@neuwo.ai)

## Installation

Install the package using pip:

```bash
pip install neuwo-api
```

Install with optional development dependencies:

```bash
# For development
pip install neuwo-api[dev]

# For testing
pip install neuwo-api[test]
```

## Requirements

- Python 3.8 or higher
- `requests` library (automatically installed)

## Quick Start

For more detailed examples and use cases, see the [examples folder](examples/) in the repository.

### REST API Client

```python
from neuwo_api import NeuwoRestClient

# Initialize client
client = NeuwoRestClient(
    token="your-rest-api-token",
    base_url="https://custom.api.com",
)

# Analyze text content
response = client.get_ai_topics(
    content="Cats make wonderful pets for modern households.",
    document_id="article-123",
    headline="Why Cats Make Great Pets"
)

# Access results
print(f"Tags: {len(response.tags)}")
for tag in response.tags:
    print(f"  - {tag.value} (score: {tag.score})")

print(f"Brand Safe: {response.brand_safety.is_safe}")
print(f"IAB Categories: {len(response.marketing_categories.iab_tier_1)}")
```

### EDGE API Client

```python
from neuwo_api import NeuwoEdgeClient

# Initialize client
client = NeuwoEdgeClient(
    token="your-edge-api-token",
    base_url="https://custom.api.com",
    default_origin="https://yourwebsite.com"  # Optional: default origin for requests
)

# Analyze article by URL
response = client.get_ai_topics(url="https://example.com/article")

# Or wait for analysis to complete (with automatic retry)
response = client.get_ai_topics_wait(
    url="https://example.com/new-article",
    max_retries=10,
    retry_interval=6
)

print(f"Found {len(response.tags)} tags for the article")
```

## Configuration

### REST Client Parameters

| Parameter  | Type  | Default      | Description                   |
| ---------- | ----- | ------------ | ----------------------------- |
| `token`    | `str` | **Required** | REST API authentication token |
| `base_url` | `str` | **Required** | Base URL for the API          |
| `timeout`  | `int` | `60`         | Request timeout in seconds    |

**Example:**

```python
client = NeuwoRestClient(
    token="your-token",
    base_url="https://custom.api.com",
    timeout=120
)
```

### EDGE Client Parameters

| Parameter        | Type  | Default      | Description                        |
| ---------------- | ----- | ------------ | ---------------------------------- |
| `token`          | `str` | **Required** | EDGE API authentication token      |
| `base_url`       | `str` | **Required** | Base URL for the API               |
| `timeout`        | `int` | `60`         | Request timeout in seconds         |
| `default_origin` | `str` | `None`       | Default Origin header for requests |

**Example:**

```python
client = NeuwoEdgeClient(
    token="your-token",
    base_url="https://custom.api.com",
    default_origin="https://yoursite.com",
    timeout=90
)
```

### API Methods

#### REST API

##### Get AI Topics

```python
response = client.get_ai_topics(
    content="Text to analyze",           # Required
    document_id="doc123",                 # Optional: save to database
    lang="en",                            # Optional: ISO 639-1 code
    publication_id="pub1",                # Optional
    headline="Article Headline",          # Optional
    tag_limit=15,                         # Optional: max tags (default: 15)
    tag_min_score=0.1,                    # Optional: min score (default: 0.1)
    marketing_limit=None,                 # Optional
    marketing_min_score=0.3,              # Optional (default: 0.3)
    include_in_sim=True,                  # Optional (default: True)
    article_url="https://example.com"     # Optional
)
```

##### Get Similar Articles

```python
articles = client.get_similar(
    document_id="doc123",                 # Required
    max_rows=10,                          # Optional: limit results
    past_days=30,                         # Optional: limit by date
    publication_ids=["pub1", "pub2"]      # Optional: filter by publication
)
```

##### Update Article

```python
from datetime import date

article = client.update_article(
    document_id="doc123",                 # Required
    published=date(2024, 1, 15),          # Optional
    headline="Updated Headline",          # Optional
    writer="Author Name",                 # Optional
    category="News",                      # Optional
    content="Updated content",            # Optional
    summary="Summary",                    # Optional
    publication_id="pub1",                # Optional
    article_url="https://example.com",    # Optional
    include_in_sim=True                   # Optional
)
```

##### Train AI Topics

```python
training_tags = client.train_ai_topics(
    document_id="doc123",                 # Required
    tags=["tag1", "tag2", "tag3"],        # Required
)
```

#### EDGE API

##### Get AI Topics (Single URL)

```python
response = client.get_ai_topics(
    url="https://example.com/article",    # Required
    origin="https://yoursite.com"         # Optional: override default origin
)
```

##### Get AI Topics with Auto-Retry

```python
response = client.get_ai_topics_wait(
    url="https://example.com/article",    # Required
    origin="https://yoursite.com",        # Optional
    max_retries=10,                       # Optional (default: 10)
    retry_interval=6,                     # Optional (default: 6s)
    initial_delay=2                       # Optional (default: 2s)
)
```

#### Raw Response Methods

All methods have `_raw` variants that return the raw `requests.Response` object:

```python
# REST
raw_response = client.get_ai_topics_raw(content="Text")
print(raw_response.status_code)
print(raw_response.text)

# EDGE
raw_response = client.get_ai_topics_raw(url="https://example.com")
print(raw_response.json())
```

## Error Handling

The SDK provides specific exceptions for different error scenarios:

```python
from neuwo_api import (
    NeuwoRestClient,
    ValidationError,
    AuthenticationError,
    NoDataAvailableError,
    ContentNotAvailableError,
    NetworkError
)

client = NeuwoRestClient(
    token="your-token",
    base_url="https://custom.api.com",
)

try:
    response = client.get_ai_topics(content="Your content here")
except ValidationError as e:
    print(f"Invalid input: {e}")
except AuthenticationError as e:
    print(f"Authentication failed: {e}")
except NoDataAvailableError as e:
    print(f"Data not yet available: {e}")
except ContentNotAvailableError as e:
    print(f"Content could not be analyzed: {e}")
except NetworkError as e:
    print(f"Network error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

### Exception Hierarchy

- `NeuwoAPIError` - Base exception for all API errors
  - `AuthenticationError` - Invalid or missing token (401)
  - `ForbiddenError` - Token lacks permissions (403)
  - `NotFoundError` - Resource not found (404)
    - `NoDataAvailableError` - URL not yet processed (404)
  - `BadRequestError` - Malformed request (400)
  - `ValidationError` - Request validation failed (422)
  - `RateLimitError` - Rate limit exceeded (429)
  - `ServerError` - Server error (5xx)
  - `NetworkError` - Network communication failed
  - `ContentNotAvailableError` - Content tagging failed

## Logging

The SDK uses Python's standard logging module. Enable logging to see detailed API communication:

```python
from neuwo_api import setup_logger
import logging

# Enable debug logging
setup_logger(level=logging.DEBUG)

# Or just warnings and errors (default)
setup_logger(level=logging.WARNING)

# Disable logging
from neuwo_api import disable_logger
disable_logger()
```

**Custom logging configuration:**

```python
import logging
from neuwo_api import get_logger

# Get the SDK logger
logger = get_logger()

# Add custom handler
handler = logging.FileHandler('neuwo_api.log')
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
```

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/neuwoai/neuwo-api-sdk-python.git
cd neuwo-api-sdk-python

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with all dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=neuwo_api --cov-report=html

# Run specific test file
pytest tests/test_rest_client.py

# Run with verbose output
pytest -v
```

<!-- ### Code Quality

```bash
# Format code
black neuwo_api/ tests/

# Sort imports
isort neuwo_api/ tests/

# Lint
flake8 neuwo_api/ tests/

# Type checking
mypy neuwo_api/
``` -->

### Building Distribution

```bash
# Clean up build artifacts
rm -rf dist/ build/ *.egg-info

# Build distribution packages
python -m build

# Upload to TestPyPI
twine upload --repository testpypi dist/*

# Upload to PyPI
twine upload dist/*
```

### Pre-publish Package Validation

Before publishing, validate your package to ensure it's configured correctly:

```bash
# Clean build the package first
rm -rf dist/ build/ *.egg-info
python -m build

# Verify package contents
tar -tzf dist/*.tar.gz

# Check distribution files for common issues
twine check dist/*

# Verify package metadata
python -m setup.py check --metadata --strict

# Test package installation (dry-run in isolated environment)
python -m pip install --dry-run --no-deps dist/*.whl

# Validate README will render correctly on PyPI
python -m readme_renderer README.md -o /tmp/README.html

# Test TestPyPI upload (dry-run)
twine check dist/* --strict
```

## CI/CD

### Automated Testing

The [Unit Tests Coverage workflow](.github/workflows/unit-tests-coverage.yaml) automatically runs on every push to `main` or `dev` branches and on pull requests:

- **Python versions tested**: 3.8, 3.9, 3.10, 3.11, 3.12
- **Coverage reporting**: Results uploaded to Codecov
- **Test execution**: Full test suite with coverage analysis

### Publishing Pipeline

The [Publish Python Package workflow](.github/workflows/publish-sdk.yaml) enables manual deployment with the following options:

#### Workflow Features:

- Manual trigger via GitHub Actions UI
- Deploy to **TestPyPI** or **PyPI**
- Upload artifacts to **GitHub Packages**
- Auto-create **GitHub releases** with tags
- Automatic version extraction from `pyproject.toml`

#### Setup Requirements:

Add GitHub secrets for API tokens:

- `PYPI_API_TOKEN` - Production PyPI token
- `TEST_PYPI_API_TOKEN` - TestPyPI token

#### Workflow Inputs

| Input               | Type    | Default  | Description                                    |
| ------------------- | ------- | -------- | ---------------------------------------------- |
| `target`            | choice  | TestPyPI | Deploy to `TestPyPI` or `PyPI`                 |
| `publish_to_github` | boolean | false    | Upload artifacts to GitHub                     |
| `create_release`    | boolean | false    | Create GitHub release with tag (only for PyPI) |

#### Usage:

1. **Testing release**:

   - Go to Actions > Publish Python Package > Run workflow
   - Select: TestPyPI
   - Test: `pip install -i https://test.pypi.org/simple/ neuwo-api`

2. **Production release**:

   - Update version in [pyproject.toml](pyproject.toml), [setup.py](setup.py) and [README.md](README.md)
   - Commit changes to repository
   - Go to Actions > Publish Python Package > Run workflow
   - Select: PyPI + Publish to GitHub Packages + Create GitHub release
   - Creates tag (e.g., `v0.2.0`), GitHub release, and publishes to PyPI

3. **Verify**:
   - Check PyPI: https://pypi.org/project/neuwo-api/
   - Check GitHub Release: https://github.com/neuwoai/neuwo-api-sdk-python/releases
   - Check packages appear in repo

#### What gets created:

- PyPI package: https://pypi.org/project/neuwo-api/
- GitHub release with `.whl` and `.tar.gz` files
- Git tag following `v{VERSION}` format
- Package artifacts in GitHub Actions

**Versioning:**

Follow [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

## Licence

This project is licensed under the MIT Licence - see the [LICENCE](LICENCE) file for details.
