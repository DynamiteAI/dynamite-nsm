import os
import sys
import shutil
from datetime import datetime
from lib import utilities
from lib.services import filebeat, pf_ring, zeek, suricata

ENV_VARS = utilities.get_environment_file_dict()


def is_agent_environment_prepared():
    return os.path.exists('/opt/dynamite/.agent_environment_prepared')


def install_agent(network_interface, agent_label, logstash_target, install_suricata=True):
    """
    :param network_interface: The network interface that the agent should analyze traffic on
    :param agent_label: A descriptive label representing the
    segment/location on your network that your agent is monitoring
    :param logstash_target: The host port combination for the target Logstash server (E.G "localhost:5044")
    :param install_suricata: If True, installs Suricata IDS alongside Zeek NSM
    :return: True, if install succeeded
    """
    zeek_installer = zeek.ZeekInstaller()
    zeek_profiler = zeek.ZeekProfiler(stderr=True)
    suricata_profiler = suricata.SuricataProfiler()
    filebeat_installer = filebeat.FileBeatInstaller()
    filebeat_profiler = filebeat.FileBeatProfiler()

    # === Check running processes/prerequisites
    if not is_agent_environment_prepared():
        sys.stderr.write('[-] The environment must first be prepared prior to agent installation. \n')
        sys.stderr.write('[-] This includes the installation of kernel development headers, '
                         'required for PF_RING kernel modules to be loaded. \n')
        sys.stderr.write('[-] To prepare the agent environment run \'dynamite prepare agent\'.\n')
        sys.stderr.flush()
        return False
    if zeek_profiler.is_running or filebeat_profiler.is_running:
        sys.stderr.write('[-] Please stop the agent before attempting re-installation.\n')
        return False
    elif install_suricata and suricata_profiler.is_running:
        sys.stderr.write('[-] Please stop the agent before attempting re-installation.\n')
        return False

    # === Install Suricata ===
    if install_suricata:
        suricata_installer = suricata.SuricataInstaller()
        if not suricata_profiler.is_downloaded:
            suricata_installer.download_suricata(stdout=True)
            suricata_installer.extract_suricata(stdout=True)
        else:
            sys.stdout.write('[+] Suricata has already been downloaded to local cache. Skipping Suricata Download.\n')
        if not suricata_profiler.is_installed:
            suricata_installer.install_dependencies()
            suricata_installer.setup_suricata(network_interface=network_interface, stdout=True)
        else:
            sys.stdout.write('[+] Suricata has already been installed on this system. '
                             'Skipping Suricata Installation.\n')

    # === Install Zeek ===
    if not zeek_profiler.is_downloaded:
        zeek_installer.download_zeek(stdout=True)
        zeek_installer.extract_zeek(stdout=True)
    else:
        sys.stdout.write('[+] Zeek has already been downloaded to local cache. Skipping Zeek Download.\n')
    if not zeek_profiler.is_installed:
        if not zeek_installer.install_dependencies():
            sys.stderr.write('[-] Could not find a native package manager. Currently [APT-GET/YUM are supported]\n')
            return False
        zeek_installer.setup_zeek(network_interface=network_interface, stdout=True)
    else:
        sys.stdout.write('[+] Zeek has already been installed on this system. Skipping Zeek Installation.\n')

    # === Install Filebeat ===
    if not filebeat_profiler.is_downloaded:
        filebeat_installer.download_filebeat(stdout=True)
        filebeat_installer.extract_filebeat(stdout=True)
    else:
        sys.stdout.write('[+] FileBeat has already been downloaded to local cache. Skipping FileBeat Download.\n')
    if not filebeat_profiler.is_installed:
        ENV_VARS = utilities.get_environment_file_dict()
        monitored_paths = [os.path.join(ENV_VARS.get('ZEEK_HOME'), 'logs/current/*.log')]
        if install_suricata:
            suricata_config = suricata.SuricataConfigurator(ENV_VARS.get('SURICATA_HOME'))
            monitored_paths.append(os.path.join(suricata_config.get_log_directory(), 'eve.json'))
        filebeat_installer.setup_filebeat(stdout=True)
        filebeat_config = filebeat.FileBeatConfigurator()
        filebeat_config.set_logstash_targets([logstash_target])
        filebeat_config.set_monitor_target_paths(monitored_paths)
        filebeat_config.set_agent_tag(agent_label)
        filebeat_config.write_config()
    else:
        sys.stdout.write(
            '[+] FileBeat has already been installed on this system. Skipping FileBeat Installation.\n')

    # === Post installation checks ===
    pf_ring_post_install_profiler = pf_ring.PFRingProfiler()
    zeek_post_install_profiler = zeek.ZeekProfiler()
    suricata_post_profiler = suricata.SuricataProfiler()
    filebeat_post_install_profiler = filebeat.FileBeatProfiler()
    if not pf_ring_post_install_profiler.is_running:
        sys.stderr.write('[-] PF_RING kernel module was not loaded properly.\n')
        return False
    if zeek_post_install_profiler.is_installed and filebeat_post_install_profiler.is_installed:
        if install_suricata:
            if suricata_post_profiler.is_installed:
                sys.stdout.write('[+] Agent installation complete. Start the agent: \'dynamite start agent\'.\n')
                sys.stdout.flush()
                return True
            else:
                sys.stderr.write('[-] Agent installation failed. Suricata did not install properly.\n')
                sys.stderr.flush()
                return False
        sys.stdout.write('[+] Agent installation complete. Start the agent: \'dynamite start agent\'.\n')
        sys.stdout.flush()
        return True
    return False


def point_agent(host, port):
    """
    Point the agent to a new logstash host

    :param host: The logstash host to forward logs too
    :param port: The service port the logstash host is listening on [5044 standard]
    """
    filebeat_config = filebeat.FileBeatConfigurator()
    filebeat_config.set_logstash_targets(['{}:{}'.format(host, port)])
    filebeat_config.write_config()
    sys.stdout.write('[+] Agent is now pointing to Logstash [{}:{}]\n'.format(host, port))
    sys.stdout.write('[+] Agent must be restarted for changes to take effect.\n')


def prepare_agent():
    """
    Install the necessary build dependencies and kernel-headers
    *** IMPORTANT A REBOOT IS REQUIRED AFTER RUNNING THIS METHOD ***

    :return: True, if successfully prepared
    """
    if is_agent_environment_prepared():
        agent_preparation_date = open('/opt/dynamite/.agent_environment_prepared').read()
        sys.stderr.write('[-] This environment has already been prepared ({}). '
                         'You can proceed with agent installation.\n'.format(agent_preparation_date))
        sys.stderr.write('[-] \'dynamite install agent\'.\n')
        sys.stderr.flush()
        return False
    pf_ring_install = pf_ring.PFRingInstaller()
    if not pf_ring_install.install_dependencies():
        sys.stderr.write('\n[-] Could not find a native package manager. Currently [APT-GET/YUM are supported]\n')
        return False
    with open('/opt/dynamite/.agent_environment_prepared', 'w') as f:
        f.write(str(datetime.utcnow()))
    sys.stdout.write('[+] *** Development Kernel Packages & Build Tools Installed. Please Reboot ***\n\n')
    sys.stdout.write('[+] After reboot, continue installation with: \'dynamite install agent\'.\n')
    sys.stdout.flush()
    return True


def profile_agent():
    """
    Get information about installation/running processes within the agent stack

    :return: A dictionary containing the status of each component
    """
    pf_ring_profiler = pf_ring.PFRingProfiler()
    filebeat_profiler = filebeat.FileBeatProfiler()
    zeek_profiler = zeek.ZeekProfiler()
    return dict(
        PF_RING=pf_ring_profiler.get_profile(),
        FILEBEAT=filebeat_profiler.get_profile(),
        ZEEK=zeek_profiler.get_profile()
    )


def start_agent():
    """
    Start the Zeek (BroCtl) and FileBeats processes

    :return: True, if started successfully
    """

    # Load service profilers
    pf_ring_profiler = pf_ring.PFRingProfiler(stderr=False)
    filebeat_profiler = filebeat.FileBeatProfiler(stderr=False)
    zeek_profiler = zeek.ZeekProfiler(stderr=False)
    suricata_profiler = suricata.SuricataProfiler(stderr=False)

    # Load service processes
    filebeat_p = filebeat.FileBeatProcess(install_directory=ENV_VARS.get('FILEBEAT_HOME'))
    zeek_p = zeek.ZeekProcess(install_directory=ENV_VARS.get('ZEEK_HOME'))

    if not (filebeat_profiler.is_installed or zeek_profiler.is_installed):
        sys.stderr.write('[-] Could not start agent. Is it installed?\n')
        sys.stderr.write('[-] dynamite install agent\n')
        return False
    if not pf_ring_profiler.is_running:
        sys.stderr.write('[-] PF_RING kernel modules were not loaded. Try running '
                         '\'modprobe pf_ring min_num_slots=32768\' as root.\n')
        return False
    sys.stdout.write('[+] Starting agent processes.\n')
    if suricata_profiler.is_installed:
        # Load Suricata process
        suricata_p = suricata.SuricataProcess(install_directory=ENV_VARS.get('SURICATA_HOME'),
                                              configuration_directory=ENV_VARS.get('SURICATA_CONFIG'))
        if not suricata_p.start(stdout=True):
            sys.stderr.write('[-] Could not start agent.suricata_process.\n')
            return False
    if not zeek_p.start(stdout=True):
        sys.stderr.write('[-] Could not start agent.zeek_process.\n')
        return False
    if not filebeat_p.start(stdout=True):
        sys.stderr.write('[-] Could not start agent.filebeat.\n')
        return False
    return True


def status_agent():
    """
    Retrieve the status of the agent processes

    :return: A tuple, where the first element is the zeek process status (string), and second element are
             the FileBeats and PF_RING status
    """

    # Load service processes
    zeek_p = zeek.ZeekProcess(install_directory=ENV_VARS.get('ZEEK_HOME'))
    filebeat_p = filebeat.FileBeatProcess(ENV_VARS.get('FILEBEAT_HOME'))

    # Load service profilers
    pf_ring_profiler = pf_ring.PFRingProfiler(stderr=False)
    filebeat_profiler = filebeat.FileBeatProfiler(stderr=False)
    zeek_profiler = zeek.ZeekProfiler(stderr=False)
    suricata_profiler = suricata.SuricataProfiler(stderr=False)

    if not (filebeat_profiler.is_installed or zeek_profiler.is_installed):
        sys.stderr.write('[-] Could not start agent. Is it installed?\n')
        sys.stderr.write('[-] dynamite install agent\n')
        return False
    agent_status = dict(
        agent_processes={
            'pf_ring': pf_ring_profiler.get_profile(),
            'filebeat': filebeat_p.status()
        }
    )
    if suricata_profiler.is_installed:
        # Load Suricata process
        suricata_p = suricata.SuricataProcess(install_directory=ENV_VARS.get('SURICATA_HOME'),
                                              configuration_directory=ENV_VARS.get('SURICATA_CONFIG'))
        agent_status['agent_processes']['suricata'] = suricata_p.status()
    return zeek_p.status(), agent_status


def stop_agent():
    """
    Stop the Zeek (BroCtl) and FileBeats processes

    :return: True, if stopped successfully
    """
    sys.stdout.write('[+] Stopping agent processes.\n')

    # Load service profilers
    filebeat_profiler = filebeat.FileBeatProfiler(stderr=True)
    zeek_profiler = zeek.ZeekProfiler(stderr=True)
    suricata_profiler = suricata.SuricataProfiler()

    # Load service processes
    zeek_p = zeek.ZeekProcess()
    filebeat_p = filebeat.FileBeatProcess(install_directory=ENV_VARS.get('FILEBEAT_HOME'))

    if not (filebeat_profiler.is_installed or zeek_profiler.is_installed):
        sys.stderr.write('[-] Could not start agent. Is it installed?\n')
        sys.stderr.write('[-] dynamite install agent\n')
        return False
    if suricata_profiler.is_installed:
        # Load Suricata process
        suricata_p = suricata.SuricataProcess(install_directory=ENV_VARS.get('SURICATA_HOME'),
                                              configuration_directory=ENV_VARS.get('SURICATA_CONFIG'))
        if not suricata_p.stop(stdout=True):
            sys.stderr.write('[-] Could not stop agent.suricata_process.\n')
            return False
    if not zeek_p.stop(stdout=True):
        sys.stderr.write('[-] Could not stop agent.zeek_process.\n')
        return False
    elif not filebeat_p.stop(stdout=True):
        sys.stderr.write('[-] Could not stop agent.filebeat.\n')
        return False
    return True


def uninstall_agent(prompt_user=True):
    """
    Uninstall the agent

    :param prompt_user: Print a warning before continuing
    :return: True, if uninstall succeeded
    """
    filebeat_profiler = filebeat.FileBeatProfiler()
    if not filebeat_profiler.is_installed:
        sys.stderr.write('[-] No agent installation detected.\n')
        return False
    filebeat_config = filebeat.FileBeatConfigurator(install_directory=ENV_VARS.get('FILEBEAT_HOME'))
    pf_profiler = pf_ring.PFRingProfiler()
    if prompt_user:
        sys.stderr.write('[-] WARNING! REMOVING THE AGENT WILL RESULT IN EVENTS NO LONGER BEING SENT TO {}.\n'.format(
            filebeat_config.get_logstash_targets()))
        resp = input('Are you sure you wish to continue? ([no]|yes): ')
        while resp not in ['', 'no', 'yes']:
            resp = input('Are you sure you wish to continue? ([no]|yes): ')
        if resp != 'yes':
            sys.stdout.write('[+] Exiting\n')
            return False
    if filebeat_profiler.is_running:
        filebeat.FileBeatProcess(install_directory=ENV_VARS.get(
            'FILEBEAT_HOME')
        ).stop(stdout=True)
    if pf_profiler.is_installed:
        shutil.rmtree(ENV_VARS.get('PF_RING_HOME'))
        os.remove('/opt/dynamite/.agent_environment_prepared')
    if filebeat_profiler.is_installed:
        shutil.rmtree(ENV_VARS.get('FILEBEAT_HOME'))
    shutil.rmtree('/tmp/dynamite/install_cache/', ignore_errors=True)
    env_lines = ''
    for line in open('/etc/environment').readlines():
        if 'FILEBEAT_HOME' in line:
            continue
        elif 'PF_RING_HOME' in line:
            continue
        env_lines += line.strip() + '\n'
    open('/etc/environment', 'w').write(env_lines)
    return True
