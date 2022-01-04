from dynamite_nsm import const
from dynamite_nsm import logger
from dynamite_nsm import utilities
from dynamite_nsm.services.updates import install as update_installer

sudoers_patch = """
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl is-enabled zeek*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl show zeek*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl stop zeek*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl start zeek*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl restart zeek*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl status zeek*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl is-enabled suricata*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl show suricata*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl stop suricata*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl start suricata*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl restart suricata*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl status suricata*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl is-enabled filebeat*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl show filebeat*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl stop filebeat*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl start filebeat*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl restart filebeat*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl status filebeat*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl is-enabled elasticsearch*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl show elasticsearch*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl stop elasticsearch*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl start elasticsearch*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl restart elasticsearch*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl status elasticsearch*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl is-enabled logstash*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl show logstash*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl stop logstash*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl start logstash*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl restart logstash*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl status logstash*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl is-enabled kibana*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl show kibana*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl stop kibana*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl start kibana*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl restart kibana*
%dynamite ALL=(root) NOPASSWD: /usr/bin/systemctl status kibana*
"""


class InstallManager:

    def __init__(self):
        if not utilities.is_root():
            raise PermissionError('You must be root to setup DynamiteNSM.')
        self.logger = logger.get_logger('setup.install', stdout=True, stdout_only=True)

    @staticmethod
    def patch_sudoers():
        include_directory = None
        with open(const.SUDOERS_FILE, 'r') as sudoers_in:
            for i, line in enumerate(sudoers_in.readlines()):
                line = line.strip()
                if line.startswith('#includedir'):
                    include_directory = ' '.join(line.split(' ')[1:])
                    break
        if not include_directory:
            include_directory = const.SUDOERS_DIRECTORY
            utilities.makedirs(include_directory)
            with open(const.SUDOERS_FILE, 'a') as sudoers_out:
                sudoers_out.write(f'\n#includedir {include_directory}')
        with open(f'{include_directory}/dynamite', 'w') as dynamite_sudoers_out:
            dynamite_sudoers_out.write(sudoers_patch)

    def setup(self):
        fresh_install_paths = [const.LOG_PATH, const.CONFIG_PATH, const.INSTALL_PATH]
        for path in fresh_install_paths:
            self.logger.info(f'Reserving {path}.')
            utilities.makedirs(path)
            utilities.set_ownership_of_file(path, user='dynamite', group='dynamite')
            utilities.set_permissions_of_file(path, 770)
        self.logger.info('Creating Dynamite NSM Environment file.')
        utilities.create_dynamite_environment_file()
        self.logger.info('Patching sudoers file.')
        self.patch_sudoers()
        self.logger.info('Checking for updates')
        update_installer.InstallManager(stdout=True, verbose=True).setup()
        self.logger.info('Setup complete. You can now install and manage services.')

