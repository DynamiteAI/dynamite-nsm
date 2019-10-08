import os
import sys
import time
import shutil
from dynamite_nsm.utilities import download_file
from dynamite_nsm.utilities import extract_archive
from dynamite_nsm.utilities import create_dynamite_root_directory


def update_default_configurations():
    create_dynamite_root_directory()
    download_file('https://github.com/DynamiteAI/dynamite-nsm-configs/raw/master/default_configs.tar.gz',
                  'default_configs.tar.gz', stdout=True)
    shutil.rmtree('/etc/dynamite/default_configs/', ignore_errors=True)
    time.sleep(1)
    try:
        print('Copying default_configs -> /etc/dynamite/default_configs')
        extract_archive('default_configs.tar.gz', '/etc/dynamite/')

    except IOError as e:
        sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))


def update_mirrors():
    create_dynamite_root_directory()
    download_file('https://github.com/DynamiteAI/dynamite-nsm-configs/raw/master/mirrors.tar.gz',
                  'mirrors.tar.gz', stdout=True)
    shutil.rmtree('/etc/dynamite/mirrors/', ignore_errors=True)
    try:
        print('Copying mirrors -> /etc/dynamite/mirrors')
        extract_archive('mirrors.tar.gz', '/etc/dynamite/')
        shutil.copytree('mirrors/', '/etc/dynamite/mirrors')
    except IOError as e:
        sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))