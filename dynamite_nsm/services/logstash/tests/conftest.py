import pytest
from dynamite_nsm.utilities import makedirs
import os
import shutil
import yaml

@pytest.fixture()
def logstash_test_dir(request):
    testdir = '/tmp/dynamite/logstash_test'
    makedirs(testdir)
    def teardown():
        if os.path.exists(testdir) and os.path.isdir(testdir):
            print("tearing down logstash test dir")
            shutil.rmtree(testdir)
    request.addfinalizer(teardown)

    return testdir

@pytest.fixture()
def logstash_test_config_yaml(logstash_test_dir):
    confdata = {
        'node.name': 'testing_ls_node',
        'path.data': '/tmp/dynamite/logstash_test/data/',
        'path.logs':
        '/var/log/dynamite/logstash',
        'pipeline.batch.delay': 50,
        'pipeline.batch.size': 125
    }
    path = f"{logstash_test_dir}/logstash.yml"
    if os.path.exists(path):
        os.remove(path)
    makedirs(logstash_test_dir)
    os.mknod(path)
    with open(path, 'w') as yamlfile:
        yamlfile.write(yaml.dump(confdata))
    return path

    
