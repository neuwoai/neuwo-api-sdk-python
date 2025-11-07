"""
EDGE API raw response examples for Neuwo API SDK.

This example shows how to use _raw methods with EDGE API to get
unprocessed HTTP responses for custom handling.
"""

import json
import os

from neuwo_api import NeuwoEdgeClient

EDGE_TOKEN = os.getenv("NEUWO_EDGE_TOKEN", "your-edge-token-here")
BASE_URL = os.getenv("NEUWO_BASE_URL", "your-api-server-base-url-here")


def get_ai_topics_raw():
    """Get raw HTTP response from EDGE GetAiTopics."""
    print("=" * 60)
    print("Example 1: Get AI Topics (Raw Response)")
    print("=" * 60)

    client = NeuwoEdgeClient(
        token=EDGE_TOKEN, base_url=BASE_URL, default_origin="https://yourwebsite.com"
    )

    url = "https://neuwo.ai/blog/2025/05/13/lets-break-the-rules-you-set-the-cpm/"

    try:
        # Get raw response
        response = client.get_ai_topics_raw(url=url)

        print(f"\nHTTP Status: {response.status_code}")
        print(f"Content-Type: {response.headers.get('Content-Type')}")
        print(f"Response size: {len(response.text)} bytes")

        # Parse JSON manually
        data = response.json()
        print("\nResponse structure:")
        print(f"  Keys: {list(data.keys())}")
        if "tags" in data:
            print(f"  Tags count: {len(data['tags'])}")
        if "url" in data:
            print(f"  URL field: {data['url']}")

        # Pretty print first tag
        if "tags" in data and data["tags"]:
            print("\nFirst tag (raw):")
            print(json.dumps(data["tags"][0], indent=2))

    except Exception as e:
        print(f"Error: {e}")


def inspect_response_headers():
    """Inspect HTTP response headers."""
    print("\n" + "=" * 60)
    print("Example 2: Inspect Response Headers")
    print("=" * 60)

    client = NeuwoEdgeClient(
        token=EDGE_TOKEN, base_url=BASE_URL, default_origin="https://mywebsite.com"
    )

    url = "https://neuwo.ai/blog/2025/05/13/lets-break-the-rules-you-set-the-cpm/"

    try:
        response = client.get_ai_topics_raw(url=url)

        print("\nAll Response Headers:")
        for key, value in response.headers.items():
            print(f"  {key}: {value}")

        print("\nRequest details:")
        print(f"  Method: {response.request.method}")
        print(f"  URL: {response.request.url}")
        print("  Headers sent:")
        for key, value in response.request.headers.items():
            if key.lower() in ["origin", "user-agent"]:
                print(f"    {key}: {value}")

    except Exception as e:
        print(f"Error: {e}")


def handle_404_manually():
    """Manually handle 404 "No data yet available" responses."""
    print("\n" + "=" * 60)
    print("Example 3: Manual 404 Handling")
    print("=" * 60)

    from neuwo_api.exceptions import NoDataAvailableError

    client = NeuwoEdgeClient(
        token=EDGE_TOKEN, base_url=BASE_URL, default_origin="https://yourwebsite.com"
    )

    # URL that might not be processed yet
    url = "https://example.com/some-new-article-123456"

    print(f"\nTrying URL: {url}")
    print("Handling 404 manually without automatic retry...\n")

    try:
        response = client.get_ai_topics_raw(url=url)

        # This won't be reached if 404
        print(f"✓ Status: {response.status_code}")
        data = response.json()
        print(f"  Tags: {len(data.get('tags', []))}")

    except NoDataAvailableError as e:
        print(f"✗ 404 Response: {e}")
        print("\nHow to handle:")
        print("  1. Queue the URL for later processing")
        print("  2. Use get_ai_topics_wait() for automatic retry")
        print("  3. Wait 30-60 seconds and try again")
    except Exception as e:
        print(f"Other error: {type(e).__name__}: {e}")


def save_responses_for_debugging():
    """Save raw responses to files for debugging."""
    print("\n" + "=" * 60)
    print("Example 4: Save Responses for Debugging")
    print("=" * 60)

    client = NeuwoEdgeClient(
        token=EDGE_TOKEN, base_url=BASE_URL, default_origin="https://yourwebsite.com"
    )

    urls_to_test = [
        "https://neuwo.ai/blog/2025/05/13/lets-break-the-rules-you-set-the-cpm/",
        "https://neuwo.ai/blog/2025/05/13/lets-break-the-rules-you-set-the-cpm/",
    ]

    print(f"\nTesting {len(urls_to_test)} URLs and saving responses...\n")

    for idx, url in enumerate(urls_to_test, 1):
        try:
            response = client.get_ai_topics_raw(url=url)

            # Save response to file
            filename = f"edge_response_{idx}.json"
            with open(filename, "w") as f:
                json.dump(response.json(), f, indent=2)

            print(f"{idx}. {url}")
            print(f"   ✓ Status: {response.status_code}")
            print(f"   ✓ Saved to: {filename}")

            # Save metadata
            meta_filename = f"edge_response_{idx}_meta.txt"
            with open(meta_filename, "w") as f:
                f.write(f"URL: {url}\n")
                f.write(f"Status: {response.status_code}\n")
                f.write(f"Response Time: {response.elapsed.total_seconds():.2f}s\n")
                f.write(f"Size: {len(response.text)} bytes\n")
                f.write("\nHeaders:\n")
                for key, value in response.headers.items():
                    f.write(f"  {key}: {value}\n")

            print(f"   ✓ Metadata saved to: {meta_filename}")

        except Exception as e:
            print(f"{idx}. {url}")
            print(f"   ✗ Error: {type(e).__name__}: {e}")

        print()


def compare_response_formats():
    """Compare parsed vs raw response handling."""
    print("\n" + "=" * 60)
    print("Example 5: Parsed vs Raw Response Comparison")
    print("=" * 60)

    client = NeuwoEdgeClient(
        token=EDGE_TOKEN, base_url=BASE_URL, default_origin="https://yourwebsite.com"
    )

    url = "https://neuwo.ai/blog/2025/05/13/lets-break-the-rules-you-set-the-cpm/"

    print(f"\nURL: {url}\n")

    # Method 1: Parsed response (normal)
    print("Method 1: Using get_ai_topics() - Parsed Response")
    try:
        from neuwo_api.exceptions import NoDataAvailableError

        parsed_response = client.get_ai_topics(url=url)
        print(f"  Type: {type(parsed_response)}")
        print(f"  Tags: {len(parsed_response.tags)}")
        print(f"  Brand Safety: {parsed_response.brand_safety is not None}")
        print(
            f"  Access: response.tags[0].value = '{parsed_response.tags[0].value if parsed_response.tags else 'N/A'}'"
        )
    except NoDataAvailableError:
        print("  Status: Data not yet available")
    except Exception as e:
        print(f"  Error: {e}")

    # Method 2: Raw response
    print("\nMethod 2: Using get_ai_topics_raw() - Raw Response")
    try:
        raw_response = client.get_ai_topics_raw(url=url)
        print(f"  Type: {type(raw_response)}")
        print(f"  Status Code: {raw_response.status_code}")
        print(f"  Headers: {len(raw_response.headers)} headers")

        data = raw_response.json()
        print(f"  Tags: {len(data.get('tags', []))}")
        print(
            f"  Access: response.json()['tags'][0]['value'] = '{data['tags'][0]['value'] if data.get('tags') else 'N/A'}'"
        )

    except Exception as e:
        print(f"  Error: {type(e).__name__}: {e}")

    print("\nComparison:")
    print("  Parsed: Easy to use, type-safe, automatic error handling")
    print("  Raw: Full control, debugging info, custom processing")


if __name__ == "__main__":
    print("Neuwo EDGE API - Raw Response Examples")
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
        get_ai_topics_raw()
        inspect_response_headers()
        handle_404_manually()
        save_responses_for_debugging()
        compare_response_formats()

        print("\n" + "=" * 60)
        print("Raw response examples completed!")
        print("=" * 60)
