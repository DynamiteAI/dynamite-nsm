import pytest
from dynamite_nsm.utilities import get_environment_file_dict, makedirs
import os
import shutil


@pytest.fixture()
def dynamite_environment():
    return get_environment_file_dict()

@pytest.fixture()
def kibana_test_dir(request):
    testdir = '/tmp/dynamite/kibana_test_configs'
    makedirs(testdir)
    def teardown():
        if os.path.exists(testdir) and os.path.isdir(testdir):
            print("tearing down kibana test dir")
            shutil.rmtree(testdir)
    request.addfinalizer(teardown)

    return testdir

@pytest.fixture()
def kibana_test_config_yaml(kibana_test_dir):
    ktd = kibana_test_dir
    path = f"{ktd}/kibana.yml"
    if os.path.exists(path):
        os.remove(path)
    makedirs(ktd)
    curdir = os.path.dirname(os.path.realpath(__file__))
    fixturefile = f"{curdir}/fixtures/kibana.yml"
    shutil.copyfile(fixturefile, path)
    return path



    
