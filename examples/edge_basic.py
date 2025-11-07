"""
Basic EDGE API examples for Neuwo API SDK.

This example shows basic usage of the EDGE API client for analyzing
articles by URL. EDGE API can be called from web pages.
"""

import os

from neuwo_api import ContentNotAvailableError, NeuwoEdgeClient, NoDataAvailableError

EDGE_TOKEN = os.getenv("NEUWO_EDGE_TOKEN", "your-edge-token-here")
BASE_URL = os.getenv("NEUWO_BASE_URL", "your-api-server-base-url-here")


def analyze_single_url():
    """Analyze a single article by URL."""
    print("=" * 60)
    print("Example 1: Analyze Single URL")
    print("=" * 60)

    client = NeuwoEdgeClient(
        token=EDGE_TOKEN, base_url=BASE_URL, default_origin="https://yourwebsite.com"
    )

    # Example URL (replace with actual article URL)
    url = "https://neuwo.ai/blog/2025/05/13/lets-break-the-rules-you-set-the-cpm/"

    try:
        response = client.get_ai_topics(url=url)

        print(f"\nAnalyzed URL: {url}")
        print(f"Found {len(response.tags)} tags:")
        for tag in response.tags[:5]:
            print(f"  • {tag.value} (score: {tag.score:.4f})")

        if response.brand_safety:
            print(f"\nBrand Safe: {response.brand_safety.is_safe}")

        if response.marketing_categories and response.marketing_categories.iab_tier_1:
            print("\nIAB Categories:")
            for cat in response.marketing_categories.iab_tier_1[:3]:
                print(f"  • {cat.label}")

    except NoDataAvailableError as e:
        print(f"\n⏳ URL not yet processed: {e}")
        print("   The URL has been queued for analysis.")
        print("   Try again in 10-60 seconds or use get_ai_topics_wait()")
    except ContentNotAvailableError as e:
        print(f"\n✗ Content unavailable: {e}")
    except Exception as e:
        print(f"Error: {e}")


def analyze_with_origin():
    """Analyze URL with custom Origin header."""
    print("\n" + "=" * 60)
    print("Example 2: Analyze with Custom Origin")
    print("=" * 60)

    # Initialize with default origin
    client = NeuwoEdgeClient(
        token=EDGE_TOKEN, base_url=BASE_URL, default_origin="https://yourwebsite.com"
    )

    url = "https://neuwo.ai/blog/2025/05/13/lets-break-the-rules-you-set-the-cpm/"

    try:
        # Can override origin per request
        response = client.get_ai_topics(url=url, origin="https://different-site.com")

        print(f"\nAnalyzed: {url}")
        print(f"Tags: {', '.join([t.value for t in response.tags[:3]])}")

    except NoDataAvailableError as e:
        print(f"URL not yet processed: {e}")
    except Exception as e:
        print(f"Error: {e}")


def handle_errors():
    """Demonstrate error handling with EDGE API."""
    print("\n" + "=" * 60)
    print("Example 3: Error Handling")
    print("=" * 60)

    from neuwo_api import ValidationError

    client = NeuwoEdgeClient(
        token=EDGE_TOKEN, base_url=BASE_URL, default_origin="https://yourwebsite.com"
    )

    # Test 1: Invalid URL
    print("\nTest 1: Invalid URL format")
    try:
        response = client.get_ai_topics(url="not-a-valid-url")
    except ValidationError as e:
        print(f"  ✓ Caught ValidationError: {e}")

    # Test 2: URL not yet processed
    print("\nTest 2: URL not yet processed")
    try:
        response = client.get_ai_topics(
            url="https://neuwo.ai/blog/2025/05/13/lets-break-the-rules-you-set-the-cpm/"
        )
    except NoDataAvailableError as e:
        print(f"  ✓ URL queued for processing: {type(e).__name__}")
        print(f"     {e}")
    except Exception as e:
        print(f"  Different error: {type(e).__name__}: {e}")

    # Test 3: Successful request
    print("\nTest 3: Valid, processed URL")
    try:
        response = client.get_ai_topics(
            url="https://neuwo.ai/blog/2025/05/13/lets-break-the-rules-you-set-the-cpm/"
        )
        print(f"  ✓ Success! Received {len(response.tags)} tags")
    except NoDataAvailableError:
        print("  ⏳ URL not yet processed (will be available soon)")
    except Exception as e:
        print(f"  Error: {e}")


if __name__ == "__main__":
    print("Neuwo EDGE API - Basic Examples")
    print("=" * 60)

    if EDGE_TOKEN == "your-edge-token-here":
        print("\n⚠️  Please set your NEUWO_EDGE_TOKEN environment variable")
        print("   export NEUWO_EDGE_TOKEN='your-actual-token'")
        print("   Or edit this script and replace 'your-edge-token-here'\n")
    if BASE_URL == "your-api-server-base-url-here":
        print("\n⚠️  Please set your NEUWO_BASE_URL environment variable")
        print("   export NEUWO_BASE_URL='your-api-server-base-url'")
        print("   Or edit this script and replace 'your-api-server-base-url'\n")
    else:
        analyze_single_url()
        analyze_with_origin()
        handle_errors()

        print("\n" + "=" * 60)
        print("Examples completed!")
        print("=" * 60)
