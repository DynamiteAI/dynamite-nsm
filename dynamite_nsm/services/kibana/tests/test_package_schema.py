from dynamite_nsm.services.kibana.package.manager import PackageManifest, Package
from dynamite_nsm.services.kibana.package.schemas import ORPHAN_OBJECT_PACKAGE_MANIFEST_DATA


def test_package_manifest_validation(basic_manifest_data):
    manifest = PackageManifest(basic_manifest_data)
    for key, value in basic_manifest_data.items():
        assert getattr(manifest, key) == value


def test_package_es_input_custom_ids():
    manifest = PackageManifest(ORPHAN_OBJECT_PACKAGE_MANIFEST_DATA)
    package = Package(manifest)
    assert package.id is None
    custom_document_id = "super-special-package-id"
    es_input = package.es_input(id=custom_document_id)
    assert custom_document_id == es_input.get('id')

    
