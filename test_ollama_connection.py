#!/usr/bin/env python3

import requests
import sys

def test_ollama_connection(host):
    """Test connection to Ollama server."""
    print(f"Testing connection to: {host}")

    try:
        # Test basic connectivity
        print("1. Testing basic connectivity...")
        response = requests.get(f"{host}/api/version", timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print(f"   Version info: {response.json()}")
        else:
            print(f"   Error: {response.text}")
            return False

        # Test model listing
        print("2. Testing model listing...")
        response = requests.get(f"{host}/api/tags", timeout=10)
        if response.status_code == 200:
            models = response.json()
            print(f"   Available models: {len(models.get('models', []))}")
            for model in models.get('models', [])[:5]:  # Show first 5
                print(f"     - {model['name']}")
        else:
            print(f"   Models request failed: {response.status_code}")

        # Test specific models from config
        models_to_check = ["deepseek-r1:latest", "qwen2.5-coder:1.5b"]
        print("3. Testing specific models...")
        available_models = [m['name'] for m in models.get('models', [])]

        for model in models_to_check:
            if model in available_models:
                print(f"   ✅ {model} is available")
            else:
                print(f"   ❌ {model} is NOT available")
                print(f"   Available models: {available_models}")

        return True

    except requests.exceptions.ConnectTimeout:
        print(f"   ❌ Connection timeout - server may be down or unreachable")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"   ❌ Connection error: {e}")
        print(f"   This usually means:")
        print(f"     - Server is not running")
        print(f"     - Wrong host/port")
        print(f"     - Firewall blocking connection")
        return False
    except Exception as e:
        print(f"   ❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = "http://192.168.88.95:11434"  # Default from your config

    success = test_ollama_connection(host)

    if success:
        print("\n✅ Connection test PASSED - Ollama is accessible")
        sys.exit(0)
    else:
        print("\n❌ Connection test FAILED - Check server status and network")
        sys.exit(1)