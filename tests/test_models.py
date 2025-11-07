"""
Unit tests for Neuwo API models.
"""

from datetime import date, datetime

from neuwo_api.models import (
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


class TestTagParent:
    """Tests for TagParent model."""

    def test_from_dict(self):
        data = {
            "Level_1": {
                "value": "Technology",
                "URI": "https://tags.neuwo.ai/hierarchyID10",
            }
        }
        parent = TagParent.from_dict(data)
        assert parent.level == "Level_1"
        assert parent.value == "Technology"
        assert parent.uri == "https://tags.neuwo.ai/hierarchyID10"

    def test_from_dict_lowercase_variant(self):
        """Test parsing lowercase variant (uri field)."""
        data = {
            "Level_1": {
                "value": "Technology",
                "uri": "https://tags.neuwo.ai/hierarchyID10",
            }
        }
        parent = TagParent.from_dict(data)
        assert parent.level == "Level_1"
        assert parent.value == "Technology"
        assert parent.uri == "https://tags.neuwo.ai/hierarchyID10"

    def test_from_dict_missing_uri_field(self):
        """Test ValueError raised when neither URI nor uri is present."""
        import pytest

        data = {"Level_1": {"value": "Technology"}}
        with pytest.raises(
            ValueError, match="must contain either 'URI' or 'uri'"
        ):
            TagParent.from_dict(data)

    def test_to_dict(self):
        parent = TagParent(
            level="Level_1",
            value="Technology",
            uri="https://tags.neuwo.ai/hierarchyID10",
        )
        data = parent.to_dict()
        assert data == {
            "Level_1": {
                "value": "Technology",
                "URI": "https://tags.neuwo.ai/hierarchyID10",
            }
        }


class TestTag:
    """Tests for Tag model."""

    def test_from_dict_without_parents(self):
        data = {
            "URI": "https://tags.neuwo.ai/masterID101332",
            "value": "Domestic Animals and Pets",
            "score": "0.79728",
        }
        tag = Tag.from_dict(data)
        assert tag.uri == "https://tags.neuwo.ai/masterID101332"
        assert tag.value == "Domestic Animals and Pets"
        assert tag.score == 0.79728
        assert tag.parents == []

    def test_from_dict_with_parents(self, sample_tag_data):
        tag = Tag.from_dict(sample_tag_data)
        assert tag.uri == "https://tags.neuwo.ai/masterID101332"
        assert tag.value == "Domestic Animals and Pets"
        assert len(tag.parents) == 1
        assert len(tag.parents[0]) == 2
        assert tag.parents[0][0].level == "Level_2"

    def test_from_dict_lowercase_variant(self, sample_tag_data_lowercase):
        """Test parsing lowercase variant (uri field)."""
        tag = Tag.from_dict(sample_tag_data_lowercase)
        assert tag.uri == "https://tags.neuwo.ai/masterID101332"
        assert tag.value == "Domestic Animals and Pets"
        assert tag.score == 0.79728
        assert len(tag.parents) == 1
        assert len(tag.parents[0]) == 2
        # Verify parents are also parsed correctly with lowercase uri
        assert tag.parents[0][0].level == "Level_2"
        assert tag.parents[0][0].uri == "https://tags.neuwo.ai/hierarchyID5-6"

    def test_from_dict_lowercase_variant_without_parents(self):
        """Test parsing lowercase variant without parents."""
        data = {
            "uri": "https://tags.neuwo.ai/masterID101332",
            "value": "Domestic Animals and Pets",
            "score": "0.79728",
        }
        tag = Tag.from_dict(data)
        assert tag.uri == "https://tags.neuwo.ai/masterID101332"
        assert tag.value == "Domestic Animals and Pets"
        assert tag.score == 0.79728
        assert tag.parents == []

    def test_from_dict_missing_uri_field(self):
        """Test ValueError raised when neither URI nor uri is present."""
        import pytest

        data = {"value": "Domestic Animals and Pets", "score": "0.79728"}
        with pytest.raises(
            ValueError, match="must contain either 'URI' or 'uri'"
        ):
            Tag.from_dict(data)

    def test_to_dict(self):
        tag = Tag(
            uri="https://tags.neuwo.ai/masterID101332",
            value="Technology",
            score=0.85,
        )
        data = tag.to_dict()
        assert data["URI"] == "https://tags.neuwo.ai/masterID101332"
        assert data["value"] == "Technology"
        assert data["score"] == "0.85"


class TestBrandSafetyTag:
    """Tests for BrandSafetyTag model."""

    def test_from_dict(self, sample_brand_safety_data):
        bs = BrandSafetyTag.from_dict(sample_brand_safety_data)
        assert bs.score == 1.0
        assert bs.indication == BrandSafetyIndication.YES

    def test_from_dict_lowercase_variant_boolean(
        self, sample_brand_safety_data_lowercase
    ):
        """Test parsing lowercase variant with boolean indication."""
        bs = BrandSafetyTag.from_dict(sample_brand_safety_data_lowercase)
        assert bs.score == 1.0
        assert bs.indication == BrandSafetyIndication.YES
        assert bs.is_safe is True

    def test_from_dict_lowercase_variant_string(
        self, sample_brand_safety_data_lowercase_string
    ):
        """Test parsing lowercase variant with string indication."""
        bs = BrandSafetyTag.from_dict(
            sample_brand_safety_data_lowercase_string
        )
        assert bs.score == 0.3
        assert bs.indication == BrandSafetyIndication.NO
        assert bs.is_safe is False

    def test_from_dict_lowercase_variant_boolean_false(self):
        """Test parsing lowercase variant with boolean False."""
        data = {"score": "0.3", "indication": False}
        bs = BrandSafetyTag.from_dict(data)
        assert bs.score == 0.3
        assert bs.indication == BrandSafetyIndication.NO
        assert bs.is_safe is False

    def test_from_dict_missing_fields(self):
        """Test that ValueError is raised when required fields are missing."""
        import pytest

        data = {"score": "1.0"}
        with pytest.raises(ValueError, match="must contain either"):
            BrandSafetyTag.from_dict(data)

    def test_is_safe_property(self):
        bs = BrandSafetyTag(score=1.0, indication=BrandSafetyIndication.YES)
        assert bs.is_safe is True

        bs_unsafe = BrandSafetyTag(
            score=0.3, indication=BrandSafetyIndication.NO
        )
        assert bs_unsafe.is_safe is False

    def test_to_dict(self):
        bs = BrandSafetyTag(score=1.0, indication=BrandSafetyIndication.YES)
        data = bs.to_dict()
        assert data["score"] == "1.0"
        assert data["indication"] == "yes"


class TestTaxonomyArticle:
    """Tests for TaxonomyArticle model."""

    def test_from_dict(self, sample_taxonomy_data):
        tax = TaxonomyArticle.from_dict(sample_taxonomy_data)
        assert tax.id == "IAB16"
        assert tax.label == "Pets"
        assert tax.relevance == 0.54

    def test_to_dict(self):
        tax = TaxonomyArticle(id="IAB16", label="Pets", relevance=0.54)
        data = tax.to_dict()
        assert data["ID"] == "IAB16"
        assert data["label"] == "Pets"
        assert data["relevance"] == "0.54"


class TestMarketingCategories:
    """Tests for MarketingCategories model."""

    def test_from_dict(self, sample_marketing_categories_data):
        mc = MarketingCategories.from_dict(sample_marketing_categories_data)
        assert len(mc.iab_tier_1) == 1
        assert mc.iab_tier_1[0].id == "IAB16"
        assert len(mc.iab_tier_2) == 1
        assert len(mc.iab_tier_3) == 0

    def test_to_dict(self):
        mc = MarketingCategories(
            iab_tier_1=[
                TaxonomyArticle(id="IAB16", label="Pets", relevance=0.54)
            ]
        )
        data = mc.to_dict()
        assert len(data["iab_tier_1"]) == 1
        assert data["iab_tier_1"][0]["ID"] == "IAB16"


class TestSmartTag:
    """Tests for SmartTag model."""

    def test_from_dict(self, sample_smart_tag_data):
        st = SmartTag.from_dict(sample_smart_tag_data)
        assert st.id == "123"
        assert st.name == "animals-group"

    def test_to_dict(self):
        st = SmartTag(id="123", name="animals-group")
        data = st.to_dict()
        assert data["ID"] == "123"
        assert data["name"] == "animals-group"


class TestTrainingTag:
    """Tests for TrainingTag model."""

    def test_from_dict(self, sample_training_tag_data):
        tt = TrainingTag.from_dict(sample_training_tag_data)
        assert tt.article_id == "record_id_1"
        assert tt.tag == "tag_value_1"
        assert tt.added_date == datetime(2020, 10, 25, 8, 45, 55)

    def test_to_dict(self):
        tt = TrainingTag(
            article_id="record_id_1",
            tag="tag_value_1",
            added_date=datetime(2020, 10, 25, 8, 45, 55),
        )
        data = tt.to_dict()
        assert data["articleID"] == "record_id_1"
        assert data["tag"] == "tag_value_1"
        assert data["addedDate"] == "2020-10-25 08:45:55"


class TestSimilarArticle:
    """Tests for SimilarArticle model."""

    def test_from_dict(self, sample_similar_article_data):
        sa = SimilarArticle.from_dict(sample_similar_article_data)
        assert sa.article_id == "record_id_1"
        assert sa.headline == "headline_value_1"
        assert sa.score == 0.123
        assert sa.published == date(2024, 1, 15)

    def test_from_dict_minimal(self):
        data = {"articleID": "record_id_1", "score": 0.5}
        sa = SimilarArticle.from_dict(data)
        assert sa.article_id == "record_id_1"
        assert sa.score == 0.5
        assert sa.headline is None

    def test_to_dict(self):
        sa = SimilarArticle(
            article_id="record_id_1",
            score=0.123,
            headline="Test Headline",
            published=date(2024, 1, 15),
        )
        data = sa.to_dict()
        assert data["articleID"] == "record_id_1"
        assert data["score"] == 0.123
        assert data["headline"] == "Test Headline"
        assert data["published"] == "2024-01-15"


class TestArticle:
    """Tests for Article model."""

    def test_from_dict(self, sample_article_data):
        article = Article.from_dict(sample_article_data)
        assert article.article_id == "record_id_123"
        assert article.fetch_date == datetime(2021, 2, 1, 12, 6, 3)
        assert article.published == date(2021, 2, 2)
        assert article.headline == "News"
        assert article.include_in_sim is True

    def test_from_dict_minimal(self):
        data = {
            "articleID": "record_id_123",
            "fetchDate": "2021-02-01T12:06:03",
        }
        article = Article.from_dict(data)
        assert article.article_id == "record_id_123"
        assert article.headline is None

    def test_to_dict(self):
        article = Article(
            article_id="record_id_123",
            fetch_date=datetime(2021, 2, 1, 12, 6, 3),
            headline="Test",
            include_in_sim=True,
        )
        data = article.to_dict()
        assert data["articleID"] == "record_id_123"
        assert data["fetchDate"] == "2021-02-01T12:06:03"
        assert data["headline"] == "Test"
        assert data["includeInSim"] == "1"


class TestGetAiTopicsResponse:
    """Tests for GetAiTopicsResponse model."""

    def test_from_dict(self, sample_get_ai_topics_response):
        response = GetAiTopicsResponse.from_dict(sample_get_ai_topics_response)
        assert len(response.tags) == 1
        assert response.tags[0].value == "Domestic Animals and Pets"
        assert response.brand_safety is not None
        assert response.brand_safety.is_safe is True
        assert len(response.smart_tags) == 1

    def test_from_dict_minimal(self):
        data = {"tags": []}
        response = GetAiTopicsResponse.from_dict(data)
        assert len(response.tags) == 0
        assert response.brand_safety is None

    def test_to_dict(self):
        response = GetAiTopicsResponse(
            tags=[Tag(uri="test", value="test", score=0.5)], smart_tags=[]
        )
        data = response.to_dict()
        assert len(data["tags"]) == 1
        assert "smart_tags" in data
