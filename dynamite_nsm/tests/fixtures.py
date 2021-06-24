import pytest
from dynamite_nsm.utilities import get_environment_file_dict


@pytest.fixture()
def dynamite_environment():
    return get_environment_file_dict()
