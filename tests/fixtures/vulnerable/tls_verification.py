"""Must-detect: certificate validation turned off."""
import requests


def fetch(url):
    return requests.get(url, verify=False)
