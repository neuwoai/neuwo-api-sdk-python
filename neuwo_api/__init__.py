"""
Neuwo API SDK - Python SDK client for the Neuwo content classification API.

This SDK provides convenient access to Neuwo's REST and EDGE APIs for
AI-powered content tagging, brand safety analysis, and similarity detection.
"""

__version__ = "0.3.0"

from .edge_client import NeuwoEdgeClient
from .exceptions import (
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
from .logger import disable_logger, enable_logger, get_logger, setup_logger
from .models import (
    Article,
    BrandSafetyIndication,
    BrandSafetyTag,
    GetAiTopicsResponse,
    MarketingCategories,
    SimilarArticle,
    SmartTag,
    Tag,
    TagParent,
    TaxonomyArticle,
    TrainingTag,
)
from .rest_client import NeuwoRestClient

# Define what gets exported when using "from neuwo_api import *"
__all__ = [
    # Version
    "__version__",
    # Clients
    "NeuwoRestClient",
    "NeuwoEdgeClient",
    # Models
    "Tag",
    "TagParent",
    "BrandSafetyTag",
    "BrandSafetyIndication",
    "TaxonomyArticle",
    "MarketingCategories",
    "SmartTag",
    "TrainingTag",
    "SimilarArticle",
    "Article",
    "GetAiTopicsResponse",
    # Exceptions
    "NeuwoAPIError",
    "AuthenticationError",
    "ForbiddenError",
    "NotFoundError",
    "ValidationError",
    "BadRequestError",
    "RateLimitError",
    "ServerError",
    "NetworkError",
    "ContentNotAvailableError",
    "NoDataAvailableError",
    # Logger utilities
    "setup_logger",
    "disable_logger",
    "enable_logger",
    "get_logger",
]
