"""Must-NOT-detect: defusedxml disables external entities."""
from defusedxml.ElementTree import parse


def parse_upload(path):
    return parse(path)
