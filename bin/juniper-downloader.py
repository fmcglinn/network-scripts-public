#!/usr/bin/env python3

import sys
import subprocess
import hashlib
from urllib.parse import urlparse

def extract_filename(url):
    parsed_url = urlparse(url)
    path = parsed_url.path
    filename = path.split('/')[-1].split('?')[0]
    return filename

def calculate_sha256(filename):
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    filename = extract_filename(url)

    # Construct the curl command with proper escaping
    curl_command = ["curl", "--proxy", "juniper.networks.fail:3128", "-o", filename, url]

    # Run the curl command
    try:
        print("Downloading image: " + filename)
        print("\n\n")
        subprocess.run(curl_command, check=True)
        print("Downloaded successfully!")

        # Prompt for SHA256 sum value
        input_sha256 = input("Enter the expected SHA256 sum value: ")

        # Calculate SHA256 sum for downloaded file
        calculated_sha256 = calculate_sha256(filename)

        # Compare SHA256 sums
        if input_sha256 == calculated_sha256:
            print("SHA256 sums match! File is verified.")
        else:
            print("SHA256 sums do not match! File may be corrupted.")

        # Debug output
        print("Expected SHA256:", input_sha256)
        print("Calculated SHA256:", calculated_sha256)

    except subprocess.CalledProcessError as e:
        print("Error:", e)
