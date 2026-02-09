"""
Quick security test script.
Run with: python test_security.py
"""

import requests
import time

BASE_URL = "http://localhost:8000"

def test_rate_limiting():
    """Test login rate limiting."""
    print("Testing rate limiting...")
    
    for i in range(10):
        response = requests.post(
            f"{BASE_URL}/login",
            data={"username": "test", "password": "wrong"}
        )
        print(f"Attempt {i+1}: {response.status_code}")
        
        if response.status_code == 429:
            print("✅ Rate limiting works!")
            return
    
    print("❌ Rate limiting not working!")

def test_file_upload_size():
    """Test file upload size limits."""
    print("\nTesting file upload limits...")
    
    # Create a large file (11MB)
    large_data = b"x" * (11 * 1024 * 1024)
    
    files = {"file": ("large.txt", large_data)}
    response = requests.post(
        f"{BASE_URL}/api/experiment/upload",
        files=files,
        data={"experiment_id": 1}
    )
    
    if response.status_code == 400:
        print("✅ File size limit works!")
    else:
        print(f"❌ File size limit not working! Status: {response.status_code}")

def test_directory_traversal():
    """Test directory traversal protection."""
    print("\nTesting directory traversal protection...")
    
    response = requests.get(f"{BASE_URL}/files/tenant/../../etc/passwd")
    
    if response.status_code in [403, 404]:
        print("✅ Directory traversal protection works!")
    else:
        print(f"❌ SECURITY ISSUE! Status: {response.status_code}")

if __name__ == "__main__":
    print("=== LIMS Security Test Suite ===\n")
    
    test_rate_limiting()
    test_file_upload_size()
    test_directory_traversal()
    
    print("\n=== Tests Complete ===")