"""
Basic REST API examples for Neuwo API SDK.

This example shows basic usage of the REST API client for analyzing text content.
"""

import os

from neuwo_api import AuthenticationError, NeuwoRestClient, ValidationError

REST_TOKEN = os.getenv("NEUWO_REST_TOKEN", "your-rest-token-here")
BASE_URL = os.getenv("NEUWO_BASE_URL", "your-api-server-base-url-here")


def analyze_text():
    """Analyze text content and get AI-generated tags."""
    print("=" * 60)
    print("Example 1: Analyze Text Content")
    print("=" * 60)

    # Initialize client
    client = NeuwoRestClient(token=REST_TOKEN, base_url=BASE_URL)

    # Sample content
    content = """
    Cats make wonderful pets for modern households. These independent animals 
    are easy to care for and don't require constant attention like dogs do. 
    Cats groom themselves, use litter boxes naturally, and can stay home alone 
    during work hours. Beyond convenience, cats provide real health benefits. 
    Petting a cat reduces stress and lowers blood pressure. Their purring sound 
    is naturally calming and therapeutic.
    """

    try:
        # Analyze content
        response = client.get_ai_topics(
            content=content, headline="Why Cats Make Great Pets"
        )

        # Display tags
        print(f"\nFound {len(response.tags)} tags:")
        for tag in response.tags[:5]:  # Show top 5
            print(f"  • {tag.value} (score: {tag.score:.4f})")

        # Display brand safety
        if response.brand_safety:
            print(f"\nBrand Safe: {response.brand_safety.is_safe}")
            print(f"Safety Score: {response.brand_safety.score:.4f}")

        # Display IAB categories
        if response.marketing_categories:
            print(
                f"\nIAB Tier 1 Categories ({len(response.marketing_categories.iab_tier_1)}):"
            )
            for cat in response.marketing_categories.iab_tier_1[:3]:
                print(f"  • {cat.label} (relevance: {cat.relevance:.2f})")

        # Display smart tags
        if response.smart_tags:
            print(f"\nSmart Tags: {', '.join([st.name for st in response.smart_tags])}")

    except ValidationError as e:
        print(f"Validation error: {e}")
    except AuthenticationError as e:
        print(f"Authentication error: {e}")
    except Exception as e:
        print(f"Error: {e}")


def analyze_with_document_id():
    """Analyze content and save it to the database with a document ID."""
    print("\n" + "=" * 60)
    print("Example 2: Analyze and Save to Database")
    print("=" * 60)

    client = NeuwoRestClient(token=REST_TOKEN, base_url=BASE_URL)

    content = "Python is a high-level programming language known for its simplicity and readability."

    try:
        response = client.get_ai_topics(
            content=content,
            document_id="article-python-101",
            headline="Introduction to Python Programming",
            publication_id="tech-blog",
            article_url="https://example.com/python-intro",
            include_in_sim=True,
        )

        print("\nArticle saved with ID: article-python-101")
        print(f"Tags: {', '.join([t.value for t in response.tags[:3]])}")

    except Exception as e:
        print(f"Error: {e}")


def custom_parameters():
    """Use custom parameters to control tagging."""
    print("\n" + "=" * 60)
    print("Example 3: Custom Tagging Parameters")
    print("=" * 60)

    client = NeuwoRestClient(token=REST_TOKEN, base_url=BASE_URL)

    content = "Electric vehicles are revolutionizing the automotive industry with zero emissions."

    try:
        response = client.get_ai_topics(
            content=content,
            tag_limit=10,  # Limit to 10 tags
            tag_min_score=0.3,  # Only tags with score >= 0.3
            marketing_min_score=0.5,  # Only marketing categories with score >= 0.5
        )

        print(f"\nRetrieved {len(response.tags)} high-confidence tags")
        for tag in response.tags:
            print(f"  • {tag.value}: {tag.score:.4f}")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    print("Neuwo REST API - Basic Examples")
    print("=" * 60)

    if REST_TOKEN == "your-rest-token-here":
        print("\n⚠️  Please set your NEUWO_REST_TOKEN environment variable")
        print("   export NEUWO_REST_TOKEN='your-actual-token'")
        print("   Or edit this script and replace 'your-rest-token-here'\n")
    if BASE_URL == "your-api-server-base-url-here":
        print("\n⚠️  Please set your NEUWO_BASE_URL environment variable")
        print("   export NEUWO_BASE_URL='your-api-server-base-url'")
        print("   Or edit this script and replace 'your-api-server-base-url'\n")
    else:
        analyze_text()
        analyze_with_document_id()
        custom_parameters()

        print("\n" + "=" * 60)
        print("Examples completed successfully!")
        print("=" * 60)
