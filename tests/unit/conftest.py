import pytest
import json

@pytest.fixture()
def basic_manifest_data():
    manifest_data = {
        "name": "Package Name",
        "author": "Author McAuthorface",
        "author_email": "a.mcauthorface@dynamitepackagers.co",
        "description": "A saved objects package",
        "package_type": "saved_objects",
        "file_list": ["traffic_by_protocol.ndjson"]
    }
    return manifest_data