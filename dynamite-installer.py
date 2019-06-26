import sys

from installer import elasticsearch

if __name__ == '__main__':
    if not elasticsearch.is_root():
        sys.stderr.write('[-] This script must be run as root.')
        sys.exit(1)

    es_installer = elasticsearch.ElasticInstaller()
    es_installer.download_java(stdout=True)
    es_installer.extract_java(stdout=True)
    es_installer.setup_java()
    elasticsearch.create_dynamite_user('password')
    es_installer.download_elasticsearch(stdout=True)
    es_installer.extract_elasticsearch(stdout=True)
    es_installer.setup_elasticsearch(stdout=True)