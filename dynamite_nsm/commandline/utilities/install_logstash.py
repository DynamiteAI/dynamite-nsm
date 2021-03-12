from dynamite_nsm.commandline.service_to_commandline import SingleResponsibilityInterface
from dynamite_nsm.services.logstash import install

cmd_installer = \
    SingleResponsibilityInterface(cls=install.InstallManager, interface_name='Logstash',
                                  entry_method_name='setup',
                                  defaults=dict(download_logstash_archive=True,
                                                install_directory='/opt/dynamite/logstash',
                                                configuration_directory='/etc/dynamite/logstash',
                                                log_directory='/var/log/dynamite/logstash',
                                                stdout=True,
                                                )
                                  )

if __name__ == '__main__':
    parser = cmd_installer.get_parser()
    args = parser.parse_args()
    cmd_installer.execute(args)