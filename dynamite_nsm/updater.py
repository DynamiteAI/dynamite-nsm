import os
import sys
import time
import shutil
from dynamite_nsm import const
from dynamite_nsm.utilities import makedirs
from dynamite_nsm.utilities import download_file
from dynamite_nsm.utilities import extract_archive


def update_default_configurations():
    """
    Retrieves the latest skeleton configurations for setting up ElasticSearch, LogStash, Zeek, and Suricata

    :return: True, if retrieved successfully
    """
    shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
    makedirs(const.DEFAULT_CONFIGS, exist_ok=True)
    download_file(const.DEFAULT_CONFIGS_URL,
                  const.DEFAULT_CONFIGS_ARCHIVE_NAME, stdout=True)
    shutil.rmtree(const.DEFAULT_CONFIGS, ignore_errors=True)
    time.sleep(1)
    try:
        sys.stdout.write('[+] Copying default_configs -> {}\n'.format(const.DEFAULT_CONFIGS))
        extract_archive(os.path.join(const.INSTALL_CACHE, 'default_configs.tar.gz'), const.CONFIG_PATH)
        return True
    except IOError as e:
        sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))
    return False


def update_mirrors():
    """
    Retrieves the latest mirrors which contain the download locations for all components

    :return: True, if retrieved successfully
    """
    shutil.rmtree(const.INSTALL_CACHE, ignore_errors=True)
    makedirs(const.MIRRORS, exist_ok=True)
    download_file(const.MIRRORS_CONFIG_URL,
                  const.MIRRORS_CONFIG_ARCHIVE_NAME, stdout=True)
    shutil.rmtree(const.MIRRORS, ignore_errors=True)
    try:
        sys.stdout.write('[+] Copying mirrors -> {}\n'.format(const.MIRRORS))
        extract_archive(os.path.join(const.INSTALL_CACHE, 'mirrors.tar.gz'), const.CONFIG_PATH)
        return True
    except IOError as e:
        sys.stderr.write('[-] An error occurred while attempting to extract file. [{}]\n'.format(e))
    return False
