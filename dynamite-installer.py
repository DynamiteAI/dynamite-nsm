import sys

from installer import elasticsearch
from installer import utilities
if __name__ == '__main__':
    if not utilities.is_root():
        sys.stderr.write('[-] This script must be run as root.\n')
        sys.exit(1)

    if utilities.get_memory_available_bytes() < 6 * (1000 ** 3):
        sys.stderr.write('[-] Dynamite ElasticSearch requires at-least 6GB to run currently available [{} GB]\n'.format(
            utilities.get_memory_available_bytes()/(1024 ** 3)
        ))
        sys.exit(1)

    es_installer = elasticsearch.ElasticInstaller()
    es_installer.download_java(stdout=True)
    es_installer.extract_java(stdout=True)
    es_installer.setup_java()
    utilities.create_dynamite_user('password')
    es_installer.download_elasticsearch(stdout=True)
    es_installer.extract_elasticsearch(stdout=True)
    es_installer.setup_elasticsearch(stdout=True)
