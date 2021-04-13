import pytest
import json
from dynamite_nsm.services.kibana.package import PackageManifest
def test_package_manifest_validation(basic_manifest_data):
    manifest = PackageManifest(basic_manifest_data)
    for key, value in basic_manifest_data.items():
        assert getattr(manifest, key) == value