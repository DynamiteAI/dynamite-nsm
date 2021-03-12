from dynamite_nsm.commandline.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.kibana import install

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Kibana',
                                  interface_description='Install Kibana as a standalone component.',
                                  entry_method_name='setup',
                                  defaults=dict(download_kibana_archive=True,
                                                install_directory='/opt/dynamite/kibana',
                                                configuration_directory='/etc/dynamite/kibana',
                                                log_directory='/var/log/dynamite/kibana',
                                                stdout=True
                                                )
                                  )

if __name__ == '__main__':
    parser = interface.get_parser()
    args = parser.parse_args()
    interface.execute(args)
