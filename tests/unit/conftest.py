from _pytest.fixtures import fixture
import pytest
import warnings
import json
from dynamite_nsm.utilities import get_primary_ip_address

@pytest.fixture(scope="session", autouse=True)
def infra_warning():
    # TODO: dockerize and automate core services test enviroment creation
    WARNING_TEXT = f"Tests are configured to run against services at {get_primary_ip_address()}. " \
                    "Executing automated tests in a production environment is ill-advised " \
                    "and may lead to loss or corruption of data."
    with pytest.warns(RuntimeWarning) as wrng:
        warnings.warn(WARNING_TEXT, RuntimeWarning)
    return WARNING_TEXT

@pytest.fixture()
def primary_ip():
    return get_primary_ip_address()
    

@pytest.fixture()
def basic_manifest_data():
    manifest_data = {
        "name": "Package Name",
        "author": "Author McAuthorface",
        "author_email": "a.mcauthorface@dynamitepackagers.co",
        "description": "A saved packages package",
        "package_type": "saved_objects",
        "file_list": ["traffic_by_protocol.ndjson"]
    }
    return manifest_data