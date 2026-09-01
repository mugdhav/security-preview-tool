"""Must-NOT-detect: JSON and safe YAML loading."""
import json

import yaml


def load_session(blob):
    return json.loads(blob)


def load_config(stream):
    return yaml.safe_load(stream)
