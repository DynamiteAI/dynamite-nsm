from dynamite_nsm.services.filebeat import install
from dynamite_nsm.service_to_commandline import SingleResponsibilityInterface

interface = \
    SingleResponsibilityInterface(cls=install.InstallManager,
                                  interface_name='Filebeat',
                                  interface_description='Install Filebeat as a standalone component.',
                                  entry_method_name='setup',
                                  defaults=dict(download_filebeat_archive=True,
                                                install_directory='/opt/dynamite/filebeat',
                                                stdout=True,
                                                )
                                  )
