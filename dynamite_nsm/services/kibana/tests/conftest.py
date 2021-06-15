import pytest
from dynamite_nsm.utilities import makedirs
import os
import shutil
import yaml


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


@pytest.fixture()
def kibana_test_dir(request):
    testdir = '/tmp/dynamite/kibana_test'
    makedirs(testdir)
    def teardown():
        if os.path.exists(testdir) and os.path.isdir(testdir):
            print("tearing down kibana test dir")
            shutil.rmtree(testdir)
    request.addfinalizer(teardown)

    return testdir

@pytest.fixture()
def kibana_test_config_yaml(kibana_test_dir):
    confdata = {
        'elasticsearch.hosts': ['https://1.3.3.7:9200'],
        'elasticsearch.password': 'kibanaserver',
        'elasticsearch.requestHeadersWhitelist': ['securitytenant', 'Authorization'],
        'elasticsearch.ssl.verificationMode': 'none',
        'elasticsearch.username': 'kibanaserver',
        'newsfeed.enabled': False,
        'opendistro_security.cookie.secure': False,
        'opendistro_security.multitenancy.enabled': True,
        'opendistro_security.multitenancy.tenants.preferred': ['Private', 'Global'],
        'opendistro_security.readonly_mode.roles': ['kibana_read_only'],
        'security.showInsecureClusterWarning': False,
        'server.host': '1.3.3.7',
        'server.port': 5601,
        'telemetry.enabled': False,
        'telemetry.optIn': False
    }
    ktd = kibana_test_dir
    path = f"{ktd}/kibana.yml"
    if os.path.exists(path):
        os.remove(path)
    makedirs(ktd)
    os.mknod(path)

    with open(path, 'w') as yamlfile:
        yamlfile.write(yaml.dump(confdata))
    return path

