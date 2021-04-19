from dynamite_nsm.services.kibana.package.manager import Package
import pytest
import os
import time

def test_register_deregister_package():
  
    package_path = f"{os.path.dirname(os.path.realpath(__file__))}/zeek_piechart.tar.xz"
    package = Package.load_from_archive(package_path)
    registered = package.register()
    assert registered
    time.sleep(1)
    persisted = Package.find_by_slug(package.slug)
    assert persisted
    deregistered = persisted.deregister()
    assert deregistered
    time.sleep(1)
    persisted = Package.find_by_slug(package.slug)
    assert not persisted
    
