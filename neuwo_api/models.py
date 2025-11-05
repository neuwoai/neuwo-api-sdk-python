"""
Data models for Neuwo API responses.

This module contains classes representing all the data structures
used in the Neuwo API, with methods for parsing JSON and XML responses.
"""

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class BrandSafetyIndication(Enum):
    """Brand safety indication values."""

    YES = "yes"
    NO = "no"

    @classmethod
    def from_string(cls, value: str) -> "BrandSafetyIndication":
        """Create BrandSafetyIndication from string, case-insensitive."""
        return cls(value.lower())


@dataclass
class TagParent:
    """Represents a parent level in the tag ontology hierarchy.

    Attributes:
        level: The hierarchy level (e.g., "Level_1", "Level_2")
        value: Name of the parent category
        uri: Unique identifier for the parent category
    """

    level: str
    value: str
    uri: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TagParent":
        """Create a TagParent instance from a dictionary.

        Supports both variants:
        - Uppercase: {"Level_1": {"value": "...", "URI": "..."}}
        - Lowercase: {"Level_1": {"value": "...", "uri": "..."}}

        Args:
            data: Dictionary containing parent tag data

        Returns:
            TagParent instance

        Raises:
            ValueError: If neither URI nor uri field is present
        """
        [(level, level_data)] = data.items()
        # Handle both uppercase URI and lowercase uri
        uri_value = level_data.get("URI") or level_data.get("uri")
        if not uri_value:
            raise ValueError("TagParent data must contain either 'URI' or 'uri' field")
        return cls(level=level, value=level_data["value"], uri=uri_value)

    def to_dict(self) -> Dict[str, Dict[str, str]]:
        """Convert TagParent to dictionary."""
        return {self.level: {"value": self.value, "URI": self.uri}}


@dataclass
class Tag:
    """Represents a subject tag from content analysis.

    Attributes:
        uri: Unique ID for the subject tag
        value: Name of the tag
        score: Probability-type relevance measure (0-1)
        parents: Optional ontology upper levels for the tag
    """

    uri: str
    value: str
    score: float
    parents: List[List[TagParent]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Tag":
        """Create a Tag instance from a dictionary.

        Supports both variants:
        - Uppercase: URI field
        - Lowercase: uri field

        Args:
            data: Dictionary containing tag data

        Returns:
            Tag instance

        Raises:
            ValueError: If neither URI nor uri field is present
        """
        # Handle both uppercase URI and lowercase uri
        uri_value = data.get("URI") or data.get("uri")
        if not uri_value:
            raise ValueError("Tag data must contain either 'URI' or 'uri' field")

        parents = []
        if "parents" in data and data["parents"]:
            for group in data["parents"]:
                parents.append([TagParent.from_dict(p) for p in group])
        return cls(
            uri=uri_value,
            value=data["value"],
            score=float(data["score"]),
            parents=parents,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert Tag to dictionary."""
        result = {"URI": self.uri, "value": self.value, "score": str(self.score)}
        if self.parents:
            result["parents"] = [
                [parent.to_dict() for parent in parent_group]
                for parent_group in self.parents
            ]
        return result


@dataclass
class BrandSafetyTag:
    """Represents brand safety assessment.

    Attributes:
        score: Probability-type measure of marketing safety (0-1)
        indication: Indication of brand safety (yes/no)
    """

    score: float
    indication: BrandSafetyIndication

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BrandSafetyTag":
        """Create a BrandSafetyTag instance from a dictionary.

        Supports both variants:
        - Uppercase: BS_score (string) and BS_indication (string: "yes"/"no")
        - Lowercase: score (string) and indication (boolean)

        Args:
            data: Dictionary containing brand safety data

        Returns:
            BrandSafetyTag instance

        Raises:
            ValueError: If neither variant's required fields are present
        """
        # Try uppercase variant first (BS_score, BS_indication)
        if "BS_score" in data and "BS_indication" in data:
            return cls(
                score=float(data["BS_score"]),
                indication=BrandSafetyIndication.from_string(data["BS_indication"]),
            )
        # Try lowercase variant (score, indication)
        elif "score" in data and "indication" in data:
            score_value = float(data["score"])
            indication_value = data["indication"]

            # Handle boolean indication
            if isinstance(indication_value, bool):
                indication = BrandSafetyIndication.YES if indication_value else BrandSafetyIndication.NO
            else:
                # Handle string indication
                indication = BrandSafetyIndication.from_string(str(indication_value))

            return cls(score=score_value, indication=indication)
        else:
            raise ValueError(
                "BrandSafetyTag data must contain either (BS_score, BS_indication) or (score, indication) fields"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert BrandSafetyTag to dictionary."""
        return {"score": str(self.score), "indication": self.indication.value}

    @property
    def is_safe(self) -> bool:
        """Check if content is brand safe."""
        return self.indication == BrandSafetyIndication.YES


@dataclass
class TaxonomyArticle:
    """Represents an IAB taxonomy category.

    Attributes:
        id: IAB ID of the marketing category
        label: Name of the marketing category
        relevance: Probability type relevance measure (0-1)
    """

    id: str
    label: str
    relevance: float

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaxonomyArticle":
        """Create a TaxonomyArticle instance from a dictionary.

        Args:
            data: Dictionary containing taxonomy data

        Returns:
            TaxonomyArticle instance
        """
        return cls(
            id=data["ID"], label=data["label"], relevance=float(data["relevance"])
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert TaxonomyArticle to dictionary."""
        return {"ID": self.id, "label": self.label, "relevance": str(self.relevance)}


@dataclass
class MarketingCategories:
    """Represents all marketing categories (IAB taxonomies).

    Attributes:
        iab_tier_1: Top-level IAB Content Taxonomy
        iab_tier_2: Second-level IAB Content Taxonomy
        iab_tier_3: Third-level IAB Content Taxonomy
        iab_audience_tier_3: IAB Audience Taxonomy Tier 3
        iab_audience_tier_4: IAB Audience Taxonomy Tier 4
        iab_audience_tier_5: IAB Audience Taxonomy Tier 5
        google_topics: Google Topics taxonomy
        marketing_items: Additional marketing items
    """

    iab_tier_1: List[TaxonomyArticle] = field(default_factory=list)
    iab_tier_2: List[TaxonomyArticle] = field(default_factory=list)
    iab_tier_3: List[TaxonomyArticle] = field(default_factory=list)
    iab_audience_tier_3: List[TaxonomyArticle] = field(default_factory=list)
    iab_audience_tier_4: List[TaxonomyArticle] = field(default_factory=list)
    iab_audience_tier_5: List[TaxonomyArticle] = field(default_factory=list)
    google_topics: List[TaxonomyArticle] = field(default_factory=list)
    marketing_items: List[TaxonomyArticle] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MarketingCategories":
        """Create a MarketingCategories instance from a dictionary.

        Args:
            data: Dictionary containing marketing categories data

        Returns:
            MarketingCategories instance
        """
        return cls(
            iab_tier_1=[
                TaxonomyArticle.from_dict(item) for item in data.get("iab_tier_1", [])
            ],
            iab_tier_2=[
                TaxonomyArticle.from_dict(item) for item in data.get("iab_tier_2", [])
            ],
            iab_tier_3=[
                TaxonomyArticle.from_dict(item) for item in data.get("iab_tier_3", [])
            ],
            iab_audience_tier_3=[
                TaxonomyArticle.from_dict(item)
                for item in data.get("iab_audience_tier_3", [])
            ],
            iab_audience_tier_4=[
                TaxonomyArticle.from_dict(item)
                for item in data.get("iab_audience_tier_4", [])
            ],
            iab_audience_tier_5=[
                TaxonomyArticle.from_dict(item)
                for item in data.get("iab_audience_tier_5", [])
            ],
            google_topics=[
                TaxonomyArticle.from_dict(item)
                for item in data.get("google_topics", [])
            ],
            marketing_items=[
                TaxonomyArticle.from_dict(item)
                for item in data.get("Marketing_items", [])
            ],
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert MarketingCategories to dictionary."""
        return {
            "iab_tier_1": [item.to_dict() for item in self.iab_tier_1],
            "iab_tier_2": [item.to_dict() for item in self.iab_tier_2],
            "iab_tier_3": [item.to_dict() for item in self.iab_tier_3],
            "iab_audience_tier_3": [
                item.to_dict() for item in self.iab_audience_tier_3
            ],
            "iab_audience_tier_4": [
                item.to_dict() for item in self.iab_audience_tier_4
            ],
            "iab_audience_tier_5": [
                item.to_dict() for item in self.iab_audience_tier_5
            ],
            "google_topics": [item.to_dict() for item in self.google_topics],
            "Marketing_items": [item.to_dict() for item in self.marketing_items],
        }


@dataclass
class SmartTag:
    """Represents a smart tag.

    Attributes:
        id: ID of the smart tag
        name: Name of the smart tag
    """

    id: str
    name: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SmartTag":
        """Create a SmartTag instance from a dictionary.

        Args:
            data: Dictionary containing smart tag data

        Returns:
            SmartTag instance
        """
        return cls(id=data["ID"], name=data["name"])

    def to_dict(self) -> Dict[str, Any]:
        """Convert SmartTag to dictionary."""
        return {"ID": self.id, "name": self.name}


@dataclass
class TrainingTag:
    """Represents a training tag for an article.

    Attributes:
        article_id: Unique identifier of document/article
        tag: Label of the tag
        added_date: Datetime when the tag was added
    """

    article_id: str
    tag: str
    added_date: datetime

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TrainingTag":
        """Create a TrainingTag instance from a dictionary.

        Args:
            data: Dictionary containing training tag data

        Returns:
            TrainingTag instance
        """
        # Parse datetime string (format: YYYY-MM-DD hh:mm:ss)
        added_date = datetime.strptime(data["addedDate"], "%Y-%m-%d %H:%M:%S")
        return cls(article_id=data["articleID"], tag=data["tag"], added_date=added_date)

    def to_dict(self) -> Dict[str, Any]:
        """Convert TrainingTag to dictionary."""
        return {
            "articleID": self.article_id,
            "tag": self.tag,
            "addedDate": self.added_date.strftime("%Y-%m-%d %H:%M:%S"),
        }


@dataclass
class SimilarArticle:
    """Represents a similar article in search results.

    Attributes:
        article_id: Unique identifier of document/article
        headline: Headline of the article (optional)
        article_url: Article URL (optional)
        image_url: URL of the main image (optional)
        score: Distance-type similarity score (lower is better)
        published: Date when article was published (optional)
        publication_id: Name of the publication (optional)
    """

    article_id: str
    score: float
    headline: Optional[str] = None
    article_url: Optional[str] = None
    image_url: Optional[str] = None
    published: Optional[date] = None
    publication_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SimilarArticle":
        """Create a SimilarArticle instance from a dictionary.

        Args:
            data: Dictionary containing similar article data

        Returns:
            SimilarArticle instance
        """
        published = None
        if "published" in data and data["published"]:
            published = datetime.strptime(data["published"], "%Y-%m-%d").date()

        return cls(
            article_id=data["articleID"],
            headline=data.get("headline"),
            article_url=data.get("articleURL"),
            image_url=data.get("imageURL"),
            score=float(data["score"]),
            published=published,
            publication_id=data.get("publicationID"),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert SimilarArticle to dictionary."""
        result = {"articleID": self.article_id, "score": self.score}

        if self.headline is not None:
            result["headline"] = self.headline
        if self.article_url is not None:
            result["articleURL"] = self.article_url
        if self.image_url is not None:
            result["imageURL"] = self.image_url
        if self.published is not None:
            result["published"] = self.published.strftime("%Y-%m-%d")
        if self.publication_id is not None:
            result["publicationID"] = self.publication_id

        return result


@dataclass
class Article:
    """Represents an article in the database.

    Attributes:
        article_id: ID of the document/article
        fetch_date: Original fetch date of the article
        published: Date when article was published (optional)
        headline: Headline of the article (optional)
        writer: Writer of the article (optional)
        category: Category of the article (optional)
        content: Article content (optional)
        summary: Article summary (optional)
        publication_id: Name of the publication (optional)
        article_url: URL of the article (optional)
        image_url: URL of the main image (optional)
        include_in_sim: Whether article is included in similarity model (optional)
    """

    article_id: str
    fetch_date: datetime
    published: Optional[date] = None
    headline: Optional[str] = None
    writer: Optional[str] = None
    category: Optional[str] = None
    content: Optional[str] = None
    summary: Optional[str] = None
    publication_id: Optional[str] = None
    article_url: Optional[str] = None
    image_url: Optional[str] = None
    include_in_sim: Optional[bool] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Article":
        """Create an Article instance from a dictionary.

        Args:
            data: Dictionary containing article data

        Returns:
            Article instance
        """
        # Parse fetch_date (format: YYYY-MM-DD'T'hh:mm:ss)
        fetch_date = datetime.strptime(data["fetchDate"], "%Y-%m-%dT%H:%M:%S")

        # Parse published date if present
        published = None
        if "published" in data and data["published"]:
            published = datetime.strptime(data["published"], "%Y-%m-%d").date()

        # Parse include_in_sim (can be "0", "1", or boolean)
        include_in_sim = None
        if "includeInSim" in data and data["includeInSim"] is not None:
            val = data["includeInSim"]
            if isinstance(val, bool):
                include_in_sim = val
            elif isinstance(val, str):
                include_in_sim = val == "1"

        return cls(
            article_id=data["articleID"],
            fetch_date=fetch_date,
            published=published,
            headline=data.get("headline"),
            writer=data.get("writer"),
            category=data.get("category"),
            content=data.get("content"),
            summary=data.get("summary"),
            publication_id=data.get("publicationID"),
            article_url=data.get("articleURL"),
            image_url=data.get("imageURL"),
            include_in_sim=include_in_sim,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert Article to dictionary."""
        result = {
            "articleID": self.article_id,
            "fetchDate": self.fetch_date.strftime("%Y-%m-%dT%H:%M:%S"),
        }

        if self.published is not None:
            result["published"] = self.published.strftime("%Y-%m-%d")
        if self.headline is not None:
            result["headline"] = self.headline
        if self.writer is not None:
            result["writer"] = self.writer
        if self.category is not None:
            result["category"] = self.category
        if self.content is not None:
            result["content"] = self.content
        if self.summary is not None:
            result["summary"] = self.summary
        if self.publication_id is not None:
            result["publicationID"] = self.publication_id
        if self.article_url is not None:
            result["articleURL"] = self.article_url
        if self.image_url is not None:
            result["imageURL"] = self.image_url
        if self.include_in_sim is not None:
            result["includeInSim"] = "1" if self.include_in_sim else "0"

        return result


@dataclass
class GetAiTopicsResponse:
    """Response from GetAiTopics endpoint.

    Attributes:
        tags: List of subject tags
        brand_safety: Brand safety assessment
        marketing_categories: IAB and other marketing taxonomies
        smart_tags: List of smart tags
        url: URL that was analyzed (only in EDGE responses)
    """

    tags: List[Tag] = field(default_factory=list)
    brand_safety: Optional[BrandSafetyTag] = None
    marketing_categories: Optional[MarketingCategories] = None
    smart_tags: List[SmartTag] = field(default_factory=list)
    url: Optional[str] = None  # Only in EDGE responses

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GetAiTopicsResponse":
        """Create GetAiTopicsResponse from dictionary.

        Args:
            data: Dictionary containing response data

        Returns:
            GetAiTopicsResponse instance
        """
        return cls(
            tags=[Tag.from_dict(tag) for tag in data.get("tags", [])],
            brand_safety=BrandSafetyTag.from_dict(data["brand_safety"])
            if "brand_safety" in data
            else None,
            marketing_categories=MarketingCategories.from_dict(
                data["marketing_categories"]
            )
            if "marketing_categories" in data
            else None,
            smart_tags=[SmartTag.from_dict(tag) for tag in data.get("smart_tags", [])],
            url=data.get("url"),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert GetAiTopicsResponse to dictionary."""
        result = {
            "tags": [tag.to_dict() for tag in self.tags],
            "smart_tags": [tag.to_dict() for tag in self.smart_tags],
        }

        if self.brand_safety:
            result["brand_safety"] = self.brand_safety.to_dict()
        if self.marketing_categories:
            result["marketing_categories"] = self.marketing_categories.to_dict()
        if self.url:
            result["url"] = self.url

        return result
