"""Must-NOT-detect: fixed https host, verification on."""
import requests

TIMEOUT = 10


def fetch(path):
    url = "https://api.internal.example.org/" + path
    return requests.get(url, timeout=TIMEOUT, verify=True)
