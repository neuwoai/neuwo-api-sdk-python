"""
REST API raw response examples for Neuwo API SDK.

This example shows how to use _raw methods to get unprocessed HTTP responses
for custom processing or debugging.
"""

import json
import os

from neuwo_api import NeuwoRestClient

REST_TOKEN = os.getenv("NEUWO_REST_TOKEN", "your-rest-token-here")
BASE_URL = os.getenv("NEUWO_BASE_URL", "your-api-server-base-url-here")


def get_ai_topics_raw():
    """Get raw HTTP response from GetAiTopics endpoint."""
    print("=" * 60)
    print("Example 1: Get AI Topics (Raw Response)")
    print("=" * 60)

    client = NeuwoRestClient(token=REST_TOKEN, base_url=BASE_URL)

    try:
        # Get raw response
        response = client.get_ai_topics_raw(
            content="Python is a versatile programming language.", format="json"
        )

        print("\nHTTP Status Code: {response.status_code}")
        print("Response Headers:")
        for key, value in response.headers.items():
            print(f"  {key}: {value}")

        # Parse JSON manually
        data = response.json()
        print("\nRaw JSON Response (first 500 chars):")
        print(json.dumps(data, indent=2)[:500] + "...")

        # Custom processing
        if "tags" in data:
            print("\nCustom Processing:")
            print(f"  Total tags in response: {len(data['tags'])}")
            print(f"  Response size: {len(response.text)} bytes")

    except Exception as e:
        print(f"Error: {e}")


def get_similar_raw():
    """Get raw HTTP response from GetSimilar endpoint."""
    print("\n" + "=" * 60)
    print("Example 2: Get Similar Articles (Raw Response)")
    print("=" * 60)

    client = NeuwoRestClient(token=REST_TOKEN, base_url=BASE_URL)

    try:
        response = client.get_similar_raw(
            document_id="article-python-101", format="json", max_rows=5
        )

        print(f"\nStatus: {response.status_code}")
        print(f"Content-Type: {response.headers.get('Content-Type')}")

        # Access raw text
        print("\nRaw Response Text (first 300 chars):")
        print(response.text[:300] + "...")

        # Manual JSON parsing
        similar_articles = response.json()
        print(f"\nNumber of similar articles: {len(similar_articles)}")

    except Exception as e:
        print(f"Error: {e}")


def update_article_raw():
    """Get raw HTTP response from UpdateArticle endpoint."""
    print("\n" + "=" * 60)
    print("Example 3: Update Article (Raw Response)")
    print("=" * 60)

    from datetime import date

    client = NeuwoRestClient(token=REST_TOKEN, base_url=BASE_URL)

    try:
        response = client.update_article_raw(
            document_id="article-python-101",
            headline="Raw Response Test Article",
            published=date(2024, 1, 15),
            format="json",
        )

        print(f"\nStatus: {response.status_code}")
        print(f"Response time: {response.elapsed.total_seconds():.2f}s")

        # Access response as dict
        article_data = response.json()
        print("\nUpdated article fields:")
        for key, value in article_data.items():
            print(f"  {key}: {value}")

    except Exception as e:
        print(f"Error: {e}")


def train_ai_topics_raw():
    """Get raw HTTP response from TrainAiTopics endpoint."""
    print("\n" + "=" * 60)
    print("Example 4: Train AI Topics (Raw Response)")
    print("=" * 60)

    client = NeuwoRestClient(token=REST_TOKEN, base_url=BASE_URL)

    try:
        response = client.train_ai_topics_raw(
            document_id="article-python-101",
            tags=["python", "programming"],
            format="json",
        )

        print(f"\nStatus: {response.status_code}")

        # Check if tags were added
        training_tags = response.json()
        print("\nResponse data:")
        print(json.dumps(training_tags, indent=2))

        if isinstance(training_tags, list):
            if training_tags:
                print(f"\n✓ Added {len(training_tags)} new training tags")
            else:
                print("\n✓ All tags already existed (no new tags added)")

    except Exception as e:
        print(f"Error: {e}")


def save_raw_response_to_file():
    """Save raw response to a file for later analysis."""
    print("\n" + "=" * 60)
    print("Example 5: Save Raw Response to File")
    print("=" * 60)

    client = NeuwoRestClient(token=REST_TOKEN, base_url=BASE_URL)

    try:
        response = client.get_ai_topics_raw(
            content="Blockchain technology enables decentralized applications.",
            format="json",
        )

        # Save to file
        filename = "neuwo_response.json"
        with open(filename, "w") as f:
            json.dump(response.json(), f, indent=2)

        print(f"\n✓ Response saved to: {filename}")
        print(f"  File size: {os.path.getsize(filename)} bytes")
        print(f"  Status code: {response.status_code}")

        # Also save headers
        headers_filename = "neuwo_headers.txt"
        with open(headers_filename, "w") as f:
            for key, value in response.headers.items():
                f.write(f"{key}: {value}\n")

        print(f"  Headers saved to: {headers_filename}")

    except Exception as e:
        print(f"Error: {e}")


def handle_raw_errors():
    """Handle errors when using raw responses."""
    print("\n" + "=" * 60)
    print("Example 6: Error Handling with Raw Responses")
    print("=" * 60)

    client = NeuwoRestClient(token=REST_TOKEN, base_url=BASE_URL)

    # Test 1: Invalid content (should fail)
    print("\nTest 1: Empty content (should raise ValidationError)")
    try:
        response = client.get_ai_topics_raw(content="")
        print(f"  Unexpected success: {response.status_code}")
    except Exception as e:
        print(f"  ✓ Expected error: {type(e).__name__}: {e}")

    # Test 2: Using raw response with error handling
    print("\nTest 2: Check status before processing")
    try:
        response = client.get_ai_topics_raw(content="Valid content for testing")

        if response.status_code == 200:
            print(f"  ✓ Success: Status {response.status_code}")
            data = response.json()
            print(f"  Tags received: {len(data.get('tags', []))}")
        else:
            print(f"  ✗ Error: Status {response.status_code}")
            print(f"  Response: {response.text[:200]}")

    except Exception as e:
        print(f"  ✗ Exception: {e}")


if __name__ == "__main__":
    print("Neuwo REST API - Raw Response Examples")
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
        get_ai_topics_raw()
        get_similar_raw()
        update_article_raw()
        train_ai_topics_raw()
        save_raw_response_to_file()
        handle_raw_errors()

        print("\n" + "=" * 60)
        print("Raw response examples completed!")
        print("=" * 60)
