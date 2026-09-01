"""Must-detect: untrusted data deserialized with an unsafe loader."""
import pickle

import yaml


def load_session(blob):
    return pickle.loads(blob)


def load_config(stream):
    return yaml.load(stream)
