"""Must-detect: request target controlled by the caller."""
import requests
from flask import request


def fetch():
    return requests.get(request.args["url"])
