"""Must-detect: XML parsed without disabling external entities."""
import xml.dom.minidom


def parse_upload(data):
    return xml.dom.minidom.parseString(data)
