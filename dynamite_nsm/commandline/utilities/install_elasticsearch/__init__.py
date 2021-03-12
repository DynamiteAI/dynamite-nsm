from dynamite_nsm.commandline.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.elasticsearch import install

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Elasticsearch',
                                  interface_description='Install Elasticsearch as a standalone component.',
                                  entry_method_name='setup',
                                  defaults=dict(download_elasticsearch_archive=True,
                                                install_directory='/opt/dynamite/elasticsearch',
                                                configuration_directory='/etc/dynamite/elasticsearch',
                                                log_directory='/var/log/dynamite/elasticsearch',
                                                stdout=True,
                                                )
                                  )

if __name__ == '__main__':
    parser = interface.get_parser()
    args = parser.parse_args()
    interface.execute(args)
