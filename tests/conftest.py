"""
Shared test fixtures and configuration for Neuwo API SDK tests.
"""

import pytest
from unittest.mock import Mock


@pytest.fixture
def mock_response():
    """Create a mock response object."""
    def _mock_response(status_code=200, json_data=None, text=None):
        mock = Mock()
        mock.status_code = status_code
        mock.json.return_value = json_data or {}
        mock.text = text or ""
        return mock
    return _mock_response


@pytest.fixture
def sample_tag_data():
    """Sample tag data for testing."""
    return {
        "URI": "https://tags.neuwo.ai/masterID101332",
        "value": "Domestic Animals and Pets",
        "score": "0.79728",
        "parents": [
            [
                {
                    "Level_2": {
                        "value": "Pets & Domestic Animals",
                        "URI": "https://tags.neuwo.ai/hierarchyID5-6"
                    }
                },
                {
                    "Level_1": {
                        "value": "Free time",
                        "URI": "https://tags.neuwo.ai/hierarchyID12"
                    }
                }
            ]
        ]
    }


@pytest.fixture
def sample_brand_safety_data():
    """Sample brand safety data for testing."""
    return {
        "BS_score": "1.0",
        "BS_indication": "yes"
    }


@pytest.fixture
def sample_taxonomy_data():
    """Sample taxonomy article data for testing."""
    return {
        "ID": "IAB16",
        "label": "Pets",
        "relevance": "0.54"
    }


@pytest.fixture
def sample_smart_tag_data():
    """Sample smart tag data for testing."""
    return {
        "ID": "123",
        "name": "animals-group"
    }


@pytest.fixture
def sample_marketing_categories_data():
    """Sample marketing categories data for testing."""
    return {
        "iab_tier_1": [
            {
                "ID": "IAB16",
                "label": "Pets",
                "relevance": "0.54"
            }
        ],
        "iab_tier_2": [
            {
                "ID": "IAB16-3",
                "label": "Cats",
                "relevance": "0.54"
            }
        ],
        "iab_tier_3": [],
        "iab_audience_tier_3": [
            {
                "ID": "50",
                "label": "Demographic | Gender | Male |",
                "relevance": "0.9427"
            }
        ],
        "iab_audience_tier_4": [],
        "iab_audience_tier_5": [],
        "google_topics": [],
        "Marketing_items": []
    }


@pytest.fixture
def sample_get_ai_topics_response():
    """Sample GetAiTopics response data."""
    return {
        "tags": [
            {
                "URI": "https://tags.neuwo.ai/masterID101332",
                "value": "Domestic Animals and Pets",
                "score": "0.79728"
            }
        ],
        "brand_safety": {
            "BS_score": "1.0",
            "BS_indication": "yes"
        },
        "marketing_categories": {
            "iab_tier_1": [
                {
                    "ID": "IAB16",
                    "label": "Pets",
                    "relevance": "0.54"
                }
            ],
            "iab_tier_2": [],
            "iab_tier_3": [],
            "iab_audience_tier_3": [],
            "iab_audience_tier_4": [],
            "iab_audience_tier_5": [],
            "google_topics": [],
            "Marketing_items": []
        },
        "smart_tags": [
            {
                "ID": "123",
                "name": "animals-group"
            }
        ]
    }


@pytest.fixture
def sample_similar_article_data():
    """Sample similar article data for testing."""
    return {
        "articleID": "record_id_1",
        "headline": "headline_value_1",
        "articleURL": "https://example.com/article1",
        "imageURL": "https://example.com/image1.jpg",
        "score": 0.123,
        "published": "2024-01-15",
        "publicationID": "pub_id_1"
    }


@pytest.fixture
def sample_article_data():
    """Sample article data for testing."""
    return {
        "articleID": "record_id_123",
        "fetchDate": "2021-02-01T12:06:03",
        "published": "2021-02-02",
        "headline": "News",
        "writer": "John Smith",
        "category": "Animals",
        "content": "Cats make wonderful pets.",
        "summary": "Summarised Content",
        "publicationID": "pub_id_1",
        "articleURL": "https://www.articles.com/123",
        "imageURL": "https://www.images.com/123",
        "includeInSim": "1"
    }


@pytest.fixture
def sample_training_tag_data():
    """Sample training tag data for testing."""
    return {
        "articleID": "record_id_1",
        "tag": "tag_value_1",
        "addedDate": "2020-10-25 08:45:55"
    }
