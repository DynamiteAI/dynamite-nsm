from dynamite_nsm.services.elasticsearch import install
from dynamite_nsm.cmd.service_interfaces import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Elasticsearch Install Manager',
                                  interface_description='Install Elasticsearch as a standalone component.',
                                  entry_method_name='setup',
                                  defaults=dict(download_elasticsearch_archive=True,
                                                install_directory='/opt/dynamite/elasticsearch',
                                                configuration_directory='/etc/dynamite/elasticsearch',
                                                log_directory='/var/log/dynamite/elasticsearch',
                                                stdout=True,
                                                )
                                  )
