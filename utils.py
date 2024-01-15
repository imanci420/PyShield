import os
import re
import requests

def download_file(url):
    """Downloads the file from the provided URL and returns the file path."""
    local_filename = url.split('/')[-1]

    with requests.get(url, stream=True) as r:
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    return local_filename

def read_file(file_path):
    """Reads the content of a file and returns it as a string."""
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()