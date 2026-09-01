"""Must-detect: user-controlled filesystem path."""


def read_upload(filename):
    with open("/var/uploads/" + filename) as fh:
        return fh.read()
